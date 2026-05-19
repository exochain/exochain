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

//! HTTP route handlers — axum handler functions for all gateway endpoints.
//!
//! CONSTITUTIONAL REQUIREMENTS (do not remove):
//!   1. Vote handler MUST call `check_conflicts` + `check_and_block` (ConflictAdjudication)
//!   2. Vote handler MUST call `Kernel::adjudicate` and gate on `Verdict::Permitted` (TNC-01)
//!   3. `write_audit` MUST use `ciborium::into_writer` before blake3, not serde_json (TransparencyAccountability)

use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use decision_forum::{
    decision_object::{ActorKind, DecisionObject, Vote, VoteChoice},
    quorum::{
        QuorumCheckResult, QuorumRegistry, check_quorum_with_verified_humans,
        verify_quorum_precondition,
    },
};
use exo_core::{Did, Signature, Timestamp, hash::hash_structured, types::Hash256};
use exo_gatekeeper::{
    kernel::{ActionRequest as GatekeeperActionRequest, Verdict},
    types::{Permission, PermissionSet, Provenance},
};
use exo_governance::conflict::{
    ActionRequest as ConflictActionRequest, check_and_block, check_conflicts,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

use crate::server::{AppState, AuthenticatedSessionUser, auth_boundary_error_response};

// ── Violation 3 fix: CBOR canonical hashing ──────────────────────────────

const MAX_CANONICAL_CBOR_HASH_BYTES: usize = 64 * 1024;
const VOTE_SIGNATURE_HASH_DOMAIN: &str = "exo.gateway.vote_signature_hash.v1";
const VOTE_SIGNATURE_HASH_SCHEMA_VERSION: u16 = 1;
const VOTE_ACTION_PROVENANCE_HASH_DOMAIN: &str = "exo.gateway.vote_action_provenance.v1";
const VOTE_ACTION_PROVENANCE_HASH_SCHEMA_VERSION: u16 = 1;
const VOTE_DECISION_AFFECTED_DIDS_METADATA_KEY: &str = "affected_dids";

struct CanonicalHashWriter {
    hasher: blake3::Hasher,
    bytes_written: usize,
}

impl CanonicalHashWriter {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            bytes_written: 0,
        }
    }

    fn finalize(self) -> blake3::Hash {
        self.hasher.finalize()
    }
}

impl Write for CanonicalHashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next = self.bytes_written.checked_add(buf.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "canonical CBOR payload size overflowed hash budget accounting",
            )
        })?;
        if next > MAX_CANONICAL_CBOR_HASH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "canonical CBOR payload exceeds {MAX_CANONICAL_CBOR_HASH_BYTES} byte hash budget"
                ),
            ));
        }

        self.hasher.update(buf);
        self.bytes_written = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize `payload` using canonical CBOR then hash with blake3.
/// This is deterministic across all deployments regardless of field insertion order.
/// NEVER replace with serde_json::to_vec — JSON key ordering is non-deterministic.
fn canonical_cbor_hash(payload: &impl Serialize) -> Result<blake3::Hash, String> {
    let mut writer = CanonicalHashWriter::new();
    ciborium::into_writer(payload, &mut writer)
        .map_err(|e| format!("CBOR serialization failed: {e}"))?;
    Ok(writer.finalize())
}

fn canonical_hash(payload: &Value) -> Result<blake3::Hash, String> {
    canonical_cbor_hash(payload)
}

#[derive(Serialize)]
struct VoteSignatureHashInput<'a> {
    domain: &'static str,
    schema_version: u16,
    voter_did: &'a Did,
    decision_id: &'a str,
    choice: &'static str,
}

#[derive(Serialize)]
struct VoteActionHashInput<'a> {
    domain: &'static str,
    schema_version: u16,
    voter_did: &'a Did,
    decision_id: &'a str,
    affected_dids: Vec<&'a str>,
    choice: &'static str,
    actor_kind: &'a ActorKind,
    rationale: Option<&'a str>,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
    action: &'static str,
    required_permissions: Vec<&'static str>,
}

fn vote_choice_label(choice: VoteChoice) -> &'static str {
    match choice {
        VoteChoice::Approve => "Approve",
        VoteChoice::Reject => "Reject",
        VoteChoice::Abstain => "Abstain",
    }
}

fn vote_signature_hash(
    voter_did: &Did,
    decision_id: &str,
    choice: VoteChoice,
) -> Result<Hash256, String> {
    let payload = VoteSignatureHashInput {
        domain: VOTE_SIGNATURE_HASH_DOMAIN,
        schema_version: VOTE_SIGNATURE_HASH_SCHEMA_VERSION,
        voter_did,
        decision_id,
        choice: vote_choice_label(choice),
    };
    Ok(Hash256::from_bytes(
        *canonical_cbor_hash(&payload)?.as_bytes(),
    ))
}

fn decode_fixed_hex<const N: usize>(encoded: &str, field: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(encoded.trim()).map_err(|e| format!("{field} must be hex-encoded: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{field} must be {N} bytes, got {}", bytes.len()))
}

fn hlc_timestamp_string(timestamp: Timestamp) -> String {
    format!("hlc:{}:{}", timestamp.physical_ms, timestamp.logical)
}

fn vote_action_hash(
    request: &VoteRequest,
    voter_did: &Did,
    affected_dids: &[Did],
    actor_kind: &ActorKind,
) -> Result<Hash256, String> {
    let mut affected_dids = affected_dids.iter().map(Did::as_str).collect::<Vec<&str>>();
    affected_dids.sort_unstable();

    hash_structured(&VoteActionHashInput {
        domain: VOTE_ACTION_PROVENANCE_HASH_DOMAIN,
        schema_version: VOTE_ACTION_PROVENANCE_HASH_SCHEMA_VERSION,
        voter_did,
        decision_id: request.decision_id.as_str(),
        affected_dids,
        choice: vote_choice_label(request.choice),
        actor_kind,
        rationale: request.rationale.as_deref(),
        timestamp_physical_ms: request.timestamp_physical_ms,
        timestamp_logical: request.timestamp_logical,
        action: "Vote",
        required_permissions: vec!["vote"],
    })
    .map_err(|e| format!("vote action hash failed: {e}"))
}

fn vote_action_provenance(
    request: &VoteRequest,
    voter_did: &Did,
    affected_dids: &[Did],
    actor_kind: &ActorKind,
) -> Result<Provenance, String> {
    let timestamp = request.caller_supplied_provenance_timestamp()?;
    let action_hash = vote_action_hash(request, voter_did, affected_dids, actor_kind)?;
    let signature = request.provenance_signature()?;
    Ok(Provenance {
        actor: voter_did.clone(),
        timestamp: hlc_timestamp_string(timestamp),
        action_hash: action_hash.as_bytes().to_vec(),
        signature: signature.to_bytes(),
        public_key: Some(request.provenance_public_key()?.to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditEntryRecord {
    sequence: i64,
    prev_hash: String,
    event_hash: String,
    event_type: String,
    actor: String,
    tenant_id: String,
    decision_id: String,
    timestamp_physical_ms: i64,
    timestamp_logical: i32,
    entry_hash: String,
}

#[derive(Serialize)]
struct AuditEntryHashInput<'a> {
    sequence: i64,
    prev_hash: &'a str,
    event_hash: &'a str,
    event_type: &'a str,
    actor: &'a str,
    tenant_id: &'a str,
    decision_id: &'a str,
    timestamp_physical_ms: i64,
    timestamp_logical: i32,
}

fn compute_audit_entry_hash(input: &AuditEntryHashInput<'_>) -> Result<String, String> {
    Ok(canonical_cbor_hash(input)?.to_hex().to_string())
}

fn build_audit_entry(
    last: Option<&crate::db::AuditRow>,
    event_type: &str,
    actor: &str,
    tenant_id: &str,
    decision_id: &str,
    timestamp: Timestamp,
    payload: &Value,
) -> Result<AuditEntryRecord, String> {
    if timestamp == Timestamp::ZERO {
        return Err("audit timestamp must be caller-supplied and non-zero".to_owned());
    }

    let sequence = match last {
        Some(row) => row
            .sequence
            .checked_add(1)
            .ok_or_else(|| "audit sequence overflow".to_owned())?,
        None => 1,
    };
    let prev_hash = last
        .map(|row| row.entry_hash.clone())
        .unwrap_or_else(|| Hash256::ZERO.to_string());
    let event_hash = canonical_hash(payload)?.to_hex().to_string();
    let timestamp_physical_ms = i64::try_from(timestamp.physical_ms)
        .map_err(|_| "HLC physical timestamp exceeds i64".to_owned())?;
    let timestamp_logical = i32::try_from(timestamp.logical)
        .map_err(|_| "HLC logical timestamp exceeds i32".to_owned())?;
    let hash_input = AuditEntryHashInput {
        sequence,
        prev_hash: &prev_hash,
        event_hash: &event_hash,
        event_type,
        actor,
        tenant_id,
        decision_id,
        timestamp_physical_ms,
        timestamp_logical,
    };
    let entry_hash = compute_audit_entry_hash(&hash_input)?;

    Ok(AuditEntryRecord {
        sequence,
        prev_hash,
        event_hash,
        event_type: event_type.to_owned(),
        actor: actor.to_owned(),
        tenant_id: tenant_id.to_owned(),
        decision_id: decision_id.to_owned(),
        timestamp_physical_ms,
        timestamp_logical,
        entry_hash,
    })
}

/// Write an audit entry using CBOR-hashed event payload.
async fn write_audit_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    actor: &str,
    tenant_id: &str,
    decision_id: &str,
    timestamp: Timestamp,
    payload: &Value,
) -> Result<(), String> {
    sqlx::query("LOCK TABLE audit_entries IN EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await
        .map_err(|e| e.to_string())?;
    let last = sqlx::query_as::<_, crate::db::AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash
         FROM audit_entries ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    let entry = build_audit_entry(
        last.as_ref(),
        event_type,
        actor,
        tenant_id,
        decision_id,
        timestamp,
        payload,
    )?;
    sqlx::query(
        "INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(entry.sequence)
    .bind(&entry.prev_hash)
    .bind(&entry.event_hash)
    .bind(&entry.event_type)
    .bind(&entry.actor)
    .bind(&entry.tenant_id)
    .bind(&entry.decision_id)
    .bind(entry.timestamp_physical_ms)
    .bind(entry.timestamp_logical)
    .bind(&entry.entry_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Write an audit entry using CBOR-hashed event payload.
#[cfg(all(test, feature = "production-db"))]
async fn write_audit(
    state: &AppState,
    event_type: &str,
    actor: &str,
    tenant_id: &str,
    decision_id: &str,
    timestamp: Timestamp,
    payload: &Value,
) -> Result<(), String> {
    let db = state.require_db().map_err(|e| e.to_string())?;
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    write_audit_in_transaction(
        &mut tx,
        event_type,
        actor,
        tenant_id,
        decision_id,
        timestamp,
        payload,
    )
    .await?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ── Vote handler (decision-forum integration) ─────────────────────────────

/// Request body for casting a vote on a governance decision.
#[derive(Deserialize)]
pub struct VoteRequest {
    pub decision_id: String,
    pub voter_did: String,
    #[serde(default)]
    pub affected_dids: Vec<String>,
    pub choice: VoteChoice,
    pub actor_kind: ActorKind,
    pub rationale: Option<String>,
    pub timestamp_physical_ms: u64,
    pub timestamp_logical: u32,
    pub provenance_timestamp_physical_ms: u64,
    pub provenance_timestamp_logical: u32,
    pub provenance_public_key: String,
    pub provenance_signature: String,
}

impl VoteRequest {
    fn caller_supplied_timestamp(&self) -> Result<Timestamp, String> {
        let timestamp = Timestamp::new(self.timestamp_physical_ms, self.timestamp_logical);
        if timestamp == Timestamp::ZERO {
            return Err("vote timestamp must be caller-supplied and non-zero".to_owned());
        }
        Ok(timestamp)
    }

    fn caller_supplied_provenance_timestamp(&self) -> Result<Timestamp, String> {
        let timestamp = Timestamp::new(
            self.provenance_timestamp_physical_ms,
            self.provenance_timestamp_logical,
        );
        if timestamp == Timestamp::ZERO {
            return Err(
                "vote provenance timestamp must be caller-supplied and non-zero".to_owned(),
            );
        }
        Ok(timestamp)
    }

    fn provenance_public_key(&self) -> Result<[u8; 32], String> {
        decode_fixed_hex(&self.provenance_public_key, "provenance_public_key")
    }

    fn provenance_signature(&self) -> Result<Signature, String> {
        Ok(Signature::from_bytes(decode_fixed_hex(
            &self.provenance_signature,
            "provenance_signature",
        )?))
    }
}

fn trusted_vote_actor_kind(actor: &AuthenticatedSessionUser) -> Result<ActorKind, String> {
    if actor.status == "Active" {
        return Ok(ActorKind::Human);
    }
    Err("voter is not eligible".to_owned())
}

fn canonical_affected_dids(raw_dids: &[String]) -> Result<Vec<Did>, String> {
    if raw_dids.is_empty() {
        return Err("stored decision affected_dids metadata must not be empty".to_owned());
    }

    let mut affected = BTreeSet::new();
    for raw in raw_dids {
        let did = Did::new(raw).map_err(|e| {
            format!("stored decision affected_dids metadata contains invalid DID: {e}")
        })?;
        affected.insert(did);
    }

    if affected.is_empty() {
        return Err(
            "stored decision affected_dids metadata must contain at least one DID".to_owned(),
        );
    }

    Ok(affected.into_iter().collect())
}

fn trusted_decision_affected_dids(decision: &DecisionObject) -> Result<Vec<Did>, String> {
    let metadata_key = VOTE_DECISION_AFFECTED_DIDS_METADATA_KEY.to_owned();
    let raw = decision
        .metadata
        .get(&metadata_key)
        .ok_or_else(|| "stored decision affected_dids metadata is missing".to_owned())?;
    let raw_dids = serde_json::from_str::<Vec<String>>(raw).map_err(|e| {
        format!("stored decision affected_dids metadata must be a JSON DID array: {e}")
    })?;

    canonical_affected_dids(&raw_dids)
}

/// Handle a vote submission with conflict-of-interest and authority chain checks.
pub async fn vote_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VoteRequest>,
) -> impl IntoResponse {
    let actor = match state
        .require_authenticated_session_user_from_header(&headers)
        .await
    {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let voter_did = match exo_core::Did::new(&body.voter_did) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid voter DID"})),
            )
                .into_response();
        }
    };
    if actor.did != voter_did {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "authenticated session actor does not match voter_did"
            })),
        )
            .into_response();
    }
    let actor_kind = match trusted_vote_actor_kind(&actor) {
        Ok(actor_kind) => actor_kind,
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "voter is not eligible",
                    "message": e
                })),
            )
                .into_response();
        }
    };

    // Require DB pool — return 503 if not configured.
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "vote handler database pool unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response();
        }
    };
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, "failed to start vote transaction");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vote transaction unavailable"})),
            )
                .into_response();
        }
    };

    // Load and deserialize DecisionObject from DB.
    let row = sqlx::query(
        "SELECT tenant_id, payload FROM decisions WHERE id_hash = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(&body.decision_id)
    .bind(&actor.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let (tenant_id, payload_val): (String, Value) = match row {
        Ok(Some(r)) => {
            let tenant_id = match r.try_get::<String, _>("tenant_id") {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "decision row missing tenant_id");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "decision record unavailable"})),
                    )
                        .into_response();
                }
            };
            let payload = match r.try_get::<Value, _>("payload") {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, "decision row missing payload");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "decision record unavailable"})),
                    )
                        .into_response();
                }
            };
            (tenant_id, payload)
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "decision not found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load decision for vote");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "decision lookup failed"})),
            )
                .into_response();
        }
    };

    let mut decision: DecisionObject = match serde_json::from_value(payload_val) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "failed to deserialize decision payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "decision payload invalid"})),
            )
                .into_response();
        }
    };

    // Reject votes on terminal decisions (TNC-08 immutability).
    if decision.is_terminal() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "decision is in a terminal state and cannot accept further votes"})),
        )
            .into_response();
    }

    let affected_dids = match trusted_decision_affected_dids(&decision) {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(error = %e, "stored decision affected DID context unavailable");
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e})),
            )
                .into_response();
        }
    };

    // ── VIOLATION 1 FIX: ConflictAdjudication ───────────────────────────
    // Check if voter has a declared conflict of interest on this decision.
    let declarations = match state
        .load_blocking_conflict_declarations_for_vote(&voter_did, &affected_dids)
        .await
    {
        Ok(declarations) => declarations,
        Err(e) => {
            tracing::error!(error = %e, "failed to load conflict declarations");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "conflict register unavailable"})),
            )
                .into_response();
        }
    };
    let conflict_action = ConflictActionRequest {
        action_id: body.decision_id.clone(),
        actor_did: voter_did.clone(),
        affected_dids: affected_dids.clone(),
        description: format!("Vote on {}", body.decision_id),
    };
    let conflicts = check_conflicts(&voter_did, &conflict_action, &declarations);
    if let Err(err) = check_and_block(&voter_did, &conflicts) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "must recuse due to conflict of interest",
                "reason": err.to_string()
            })),
        )
            .into_response();
    }

    let provenance = match vote_action_provenance(&body, &voter_did, &affected_dids, &actor_kind) {
        Ok(provenance) => provenance,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response();
        }
    };

    // ── VIOLATION 2 FIX: TNC-01 Authority Chain / Governor Clearance ────
    let gk_action = GatekeeperActionRequest {
        actor: voter_did.clone(),
        action: "Vote".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("vote")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    let mut ctx = state
        .build_adjudication_context(&voter_did, &gk_action.required_permissions)
        .await;
    ctx.provenance = Some(provenance);
    match state.kernel.adjudicate(&gk_action, &ctx) {
        Verdict::Permitted => { /* proceed */ }
        Verdict::Denied { violations } => {
            let reasons: Vec<_> = violations.iter().map(|v| &v.description).collect();
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "clearance denied", "violations": reasons})),
            )
                .into_response();
        }
        Verdict::Escalated { reason } => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "escalated", "reason": reason})),
            )
                .into_response();
        }
    }

    // Verify quorum precondition (TNC-07): enough tenant-scoped eligible
    // voters must exist before accepting the vote.
    let registry = QuorumRegistry::with_defaults();
    let eligible = match crate::db::count_quorum_eligible_voters_in_transaction(
        &mut tx,
        &actor.tenant_id,
        decision.class,
    )
    .await
    {
        Ok(counts) => counts,
        Err(e) => {
            tracing::error!(error = %e, "failed to count eligible voters");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "registry unavailable"})),
            )
                .into_response();
        }
    };
    match verify_quorum_precondition(
        &registry,
        decision.class,
        eligible.eligible_voters,
        eligible.eligible_human_voters,
    ) {
        Ok(true) => { /* enough eligible voters — proceed */ }
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "insufficient eligible voters to potentially reach quorum"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "quorum precondition check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "quorum precondition failed"})),
            )
                .into_response();
        }
    }

    // Build the typed Vote with caller-supplied HLC metadata (AGENTS.md §1).
    let timestamp = match body.caller_supplied_timestamp() {
        Ok(timestamp) => timestamp,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response();
        }
    };
    let signature_hash = match vote_signature_hash(&voter_did, &body.decision_id, body.choice) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(error = %e, "failed to hash vote signature payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vote signature hash failed"})),
            )
                .into_response();
        }
    };
    let vote = Vote {
        voter_did: voter_did.clone(),
        choice: body.choice,
        actor_kind: actor_kind.clone(),
        timestamp,
        signature_hash,
    };

    // Add vote — rejects duplicates (TNC-07 voter independence).
    if let Err(e) = decision.add_vote(vote) {
        tracing::error!(error = %e, "decision rejected vote");
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "vote rejected"})),
        )
            .into_response();
    }

    // Check quorum post-vote to include status in response.
    let verified_human_voter_dids = match state
        .verified_human_voter_dids(&actor.tenant_id, &decision.votes)
        .await
    {
        Ok(voters) => voters,
        Err(e) => {
            tracing::error!(error = %e, "failed to derive verified human voters");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "human voter registry unavailable"})),
            )
                .into_response();
        }
    };
    let quorum_result =
        match check_quorum_with_verified_humans(&registry, &decision, &verified_human_voter_dids) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "quorum evaluation failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "quorum evaluation failed"})),
                )
                    .into_response();
            }
        };

    // Serialize updated DecisionObject back to JSON for DB persistence.
    let updated_payload = match serde_json::to_value(&decision) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize decision payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "decision serialization failed"})),
            )
                .into_response();
        }
    };

    let audit_payload = serde_json::json!({
        "event": "VoteCast",
        "decision_id": body.decision_id.as_str(),
        "tenant_id": tenant_id.as_str(),
        "voter": body.voter_did.as_str(),
        "choice": body.choice,
        "timestamp_physical_ms": timestamp.physical_ms,
        "timestamp_logical": timestamp.logical,
    });

    // Persist updated decision.
    if let Err(e) =
        sqlx::query("UPDATE decisions SET payload = $1 WHERE id_hash = $2 AND tenant_id = $3")
            .bind(&updated_payload)
            .bind(&body.decision_id)
            .bind(&actor.tenant_id)
            .execute(&mut *tx)
            .await
    {
        tracing::error!(error = %e, "failed to persist vote");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "decision persistence failed"})),
        )
            .into_response();
    }

    // ── VIOLATION 3 FIX: CBOR canonical audit hash ──────────────────────
    if let Err(e) = write_audit_in_transaction(
        &mut tx,
        "VoteCast",
        &body.voter_did,
        &tenant_id,
        &body.decision_id,
        timestamp,
        &audit_payload,
    )
    .await
    {
        tracing::error!(error = %e, "audit write failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "audit write failed"})),
        )
            .into_response();
    }
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, "failed to commit vote transaction");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "decision persistence failed"})),
        )
            .into_response();
    }

    // Build quorum summary for response.
    let quorum_status = match quorum_result {
        QuorumCheckResult::Met {
            total_votes,
            approve_count,
            approve_pct,
        } => serde_json::json!({
            "status": "met",
            "total_votes": total_votes,
            "approve_count": approve_count,
            "approve_pct": approve_pct,
        }),
        QuorumCheckResult::NotMet { reason } => serde_json::json!({
            "status": "not_met",
            "reason": reason,
        }),
        QuorumCheckResult::Degraded {
            reason,
            available,
            required,
        } => serde_json::json!({
            "status": "degraded",
            "reason": reason,
            "available": available,
            "required": required,
        }),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "vote_recorded": true,
            "decision": updated_payload,
            "quorum": quorum_status,
        })),
    )
        .into_response()
}

// ── Health handler ────────────────────────────────────────────────────────

/// Health check handler that verifies database connectivity.
pub async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.require_db() {
        Ok(pool) => match sqlx::query("SELECT 1").execute(pool).await {
            Ok(_) => (
                StatusCode::OK,
                Json(serde_json::json!({"status": "ok", "db": "connected"})),
            )
                .into_response(),
            Err(e) => {
                tracing::error!(error = %e, "database health check failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "status": "degraded",
                        "error": "database health check failed"
                    })),
                )
                    .into_response()
            }
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "no_db_configured"})),
        )
            .into_response(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn signed_vote_request_json(
        voter: &str,
        decision_id: &str,
        affected_dids: &[&str],
        choice: VoteChoice,
        actor_kind: ActorKind,
        timestamp: Timestamp,
    ) -> serde_json::Value {
        let voter_did = Did::new(voter).expect("valid voter DID");
        let affected = affected_dids
            .iter()
            .map(|did| Did::new(did).expect("valid affected DID"))
            .collect::<Vec<_>>();
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let provenance_timestamp = Timestamp::new(timestamp.physical_ms, timestamp.logical);
        let request = VoteRequest {
            decision_id: decision_id.to_owned(),
            voter_did: voter.to_owned(),
            affected_dids: affected_dids.iter().map(|did| (*did).to_owned()).collect(),
            choice,
            actor_kind: actor_kind.clone(),
            rationale: None,
            timestamp_physical_ms: timestamp.physical_ms,
            timestamp_logical: timestamp.logical,
            provenance_timestamp_physical_ms: provenance_timestamp.physical_ms,
            provenance_timestamp_logical: provenance_timestamp.logical,
            provenance_public_key: hex::encode(public_key.as_bytes()),
            provenance_signature: String::new(),
        };
        let action_hash = vote_action_hash(&request, &voter_did, &affected, &actor_kind)
            .expect("vote action hash");
        let mut provenance = Provenance {
            actor: voter_did,
            timestamp: hlc_timestamp_string(provenance_timestamp),
            action_hash: action_hash.as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message = exo_gatekeeper::provenance_signature_message(&provenance)
            .expect("canonical provenance payload");
        let signature = exo_core::crypto::sign(message.as_bytes(), &secret_key);
        provenance.signature = signature.to_bytes();

        serde_json::json!({
            "decision_id": decision_id,
            "voter_did": voter,
            "affected_dids": affected_dids,
            "choice": choice,
            "actor_kind": actor_kind,
            "rationale": null,
            "timestamp_physical_ms": timestamp.physical_ms,
            "timestamp_logical": timestamp.logical,
            "provenance_timestamp_physical_ms": provenance_timestamp.physical_ms,
            "provenance_timestamp_logical": provenance_timestamp.logical,
            "provenance_public_key": hex::encode(public_key.as_bytes()),
            "provenance_signature": hex::encode(provenance.signature),
        })
    }

    // Violation 3: canonical_hash must be deterministic
    #[test]
    fn canonical_hash_is_deterministic() {
        let payload = serde_json::json!({"b": 2, "a": 1});
        let h1 = canonical_hash(&payload).expect("hash ok");
        let h2 = canonical_hash(&payload).expect("hash ok");
        assert_eq!(h1, h2, "CBOR hash must be deterministic");
    }

    // Violation 3: canonical_hash must be field-order independent
    #[test]
    fn canonical_hash_is_field_order_independent() {
        // serde_json::Map uses BTreeMap by default — inserts are always alphabetical.
        // This test ensures that remains true and CBOR output is key-order stable.
        let p1 = serde_json::json!({"b": 2, "a": 1}); // stored as {a:1, b:2}
        let p2 = serde_json::json!({"a": 1, "b": 2}); // stored as {a:1, b:2}
        let h1 = canonical_hash(&p1).expect("hash ok");
        let h2 = canonical_hash(&p2).expect("hash ok");
        assert_eq!(h1, h2, "CBOR hash must be field-order independent");
    }

    // Violation 3: JSON and CBOR hashes must differ to confirm CBOR is used
    #[test]
    fn cbor_hash_differs_from_json_hash() {
        let payload = serde_json::json!({"event": "vote", "actor": "did:exo:alice"});
        let cbor_hash = canonical_hash(&payload).expect("hash ok");
        let json_bytes = serde_json::to_vec(&payload).expect("json ok");
        let json_hash = blake3::hash(&json_bytes);
        assert_ne!(cbor_hash, json_hash, "CBOR and JSON hashes must differ");
    }

    #[test]
    fn canonical_hash_rejects_payloads_above_hash_budget() {
        let payload = serde_json::json!({"event": "vote_recorded", "body": "x".repeat(70_000)});
        let err = canonical_hash(&payload)
            .expect_err("oversized CBOR payload must be rejected before unbounded buffering");

        assert!(
            err.contains("canonical CBOR payload exceeds"),
            "error should identify the canonical CBOR hash budget: {err}"
        );
    }

    #[test]
    fn vote_signature_hash_is_domain_separated_cbor() {
        let voter = Did::new("did:exo:alice").expect("valid DID");

        let first = vote_signature_hash(&voter, "decision-1", VoteChoice::Approve)
            .expect("vote signature hash");
        let second = vote_signature_hash(&voter, "decision-1", VoteChoice::Approve)
            .expect("vote signature hash");
        let changed_choice = vote_signature_hash(&voter, "decision-1", VoteChoice::Reject)
            .expect("vote signature hash");
        let legacy_debug_concat = Hash256::digest(b"did:exo:alice:decision-1:Approve");

        assert_eq!(first, second);
        assert_ne!(first, changed_choice);
        assert_ne!(
            first, legacy_debug_concat,
            "vote signature_hash must not match the legacy raw concat/Debug preimage"
        );
    }

    #[test]
    fn vote_action_hash_binds_decision_choice_and_affected_dids() {
        let voter = Did::new("did:exo:alice").expect("valid DID");
        let affected = vec![
            Did::new("did:exo:tenant-b").expect("valid DID"),
            Did::new("did:exo:tenant-a").expect("valid DID"),
        ];
        let request: VoteRequest = serde_json::from_value(signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-b", "did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        ))
        .expect("signed vote request");

        let trusted_actor_kind = ActorKind::Human;
        let baseline = vote_action_hash(&request, &voter, &affected, &trusted_actor_kind)
            .expect("vote action hash");

        let mut changed_decision = request;
        changed_decision.decision_id = "decision-2".to_owned();
        let changed_decision_hash =
            vote_action_hash(&changed_decision, &voter, &affected, &trusted_actor_kind)
                .expect("vote action hash");
        assert_ne!(baseline, changed_decision_hash);

        let mut changed_choice = changed_decision;
        changed_choice.decision_id = "decision-1".to_owned();
        changed_choice.choice = VoteChoice::Reject;
        let changed_choice_hash =
            vote_action_hash(&changed_choice, &voter, &affected, &trusted_actor_kind)
                .expect("vote action hash");
        assert_ne!(baseline, changed_choice_hash);

        let changed_affected = vec![Did::new("did:exo:tenant-c").expect("valid DID")];
        let changed_affected_hash = vote_action_hash(
            &changed_choice,
            &voter,
            &changed_affected,
            &trusted_actor_kind,
        )
        .expect("vote action hash");
        assert_ne!(baseline, changed_affected_hash);

        let reordered_affected = vec![
            Did::new("did:exo:tenant-a").expect("valid DID"),
            Did::new("did:exo:tenant-b").expect("valid DID"),
        ];
        let reordered_hash = vote_action_hash(
            &changed_choice,
            &voter,
            &reordered_affected,
            &trusted_actor_kind,
        )
        .expect("vote action hash");
        assert_ne!(baseline, reordered_hash);
        assert_eq!(
            changed_choice_hash, reordered_hash,
            "affected DID ordering must not alter the canonical vote action hash"
        );
    }

    #[test]
    fn vote_action_hash_binds_trusted_actor_kind_not_request_body_actor_kind() {
        let voter = Did::new("did:exo:alice").expect("valid DID");
        let affected = vec![Did::new("did:exo:tenant-a").expect("valid DID")];
        let mut request: VoteRequest = serde_json::from_value(signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        ))
        .expect("signed vote request");

        let trusted_actor_kind = ActorKind::Human;
        let baseline = vote_action_hash(&request, &voter, &affected, &trusted_actor_kind)
            .expect("vote action hash");
        request.actor_kind = ActorKind::AiAgent {
            delegation_id: "delegation-1".to_owned(),
            ceiling_class: decision_forum::decision_object::DecisionClass::Routine,
        };
        let client_claim_changed =
            vote_action_hash(&request, &voter, &affected, &trusted_actor_kind)
                .expect("vote action hash");
        let trusted_actor_changed =
            vote_action_hash(&request, &voter, &affected, &request.actor_kind)
                .expect("vote action hash");

        assert_eq!(
            baseline, client_claim_changed,
            "changing only request.actor_kind must not alter a trusted vote action hash"
        );
        assert_ne!(
            baseline, trusted_actor_changed,
            "changing the trusted actor kind must alter the vote action hash"
        );
    }

    #[test]
    fn vote_action_provenance_verifies_with_declared_public_key() {
        let voter = Did::new("did:exo:alice").expect("valid DID");
        let affected = vec![Did::new("did:exo:tenant-a").expect("valid DID")];
        let request: VoteRequest = serde_json::from_value(signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        ))
        .expect("signed vote request");
        let provenance = vote_action_provenance(&request, &voter, &affected, &ActorKind::Human)
            .expect("vote provenance");
        let message = exo_gatekeeper::provenance_signature_message(&provenance)
            .expect("canonical provenance payload");
        let public_key = exo_core::PublicKey::from_bytes(
            request
                .provenance_public_key()
                .expect("provenance public key"),
        );
        let signature = request.provenance_signature().expect("signature");

        assert!(
            exo_core::crypto::verify(message.as_bytes(), &signature, &public_key),
            "vote provenance signature must verify against its declared public key"
        );
    }

    #[test]
    fn handlers_do_not_expose_raw_internal_errors_in_http_bodies() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let prohibited = [
            r#""details": e.to_string()"#,
            r#"Json(serde_json::json!({"error": e.to_string()}))"#,
            r#"Json(serde_json::json!({"status": "degraded", "error": e.to_string()}))"#,
            r#"format!("failed to start vote transaction: {e}")"#,
            r#"format!("failed to deserialize decision: {e}")"#,
            r#"format!("serialization failed: {e}")"#,
            r#"format!("failed to persist vote: {e}")"#,
            r#"format!("failed to commit vote transaction: {e}")"#,
            r#"format!("audit write failed: {e}")"#,
        ];

        for pattern in prohibited {
            assert!(
                !production.contains(pattern),
                "HTTP response bodies must not expose raw internal error details: {pattern}"
            );
        }
    }

    #[test]
    fn handlers_do_not_emit_raw_did_fields_to_error_logs() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");

        for pattern in [
            "voter_did = %body.voter_did",
            "actor_did = %",
            "subject_did = %",
        ] {
            assert!(
                !production.contains(pattern),
                "handler logs must not emit raw DID identifiers: {pattern}"
            );
        }
    }

    #[test]
    fn vote_handler_does_not_lock_registry_on_async_worker() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");

        for needle in [
            "state.registry.read()",
            "state.registry.write()",
            ".registry\n        .read()",
            ".registry\n        .write()",
        ] {
            assert!(
                !production.contains(needle),
                "async vote handler must not acquire std::sync::RwLock on a Tokio worker: {needle}"
            );
        }
    }

    #[test]
    fn audit_entry_record_chains_from_previous_entry() {
        let previous = crate::db::AuditRow {
            sequence: 41,
            prev_hash: Hash256::ZERO.to_string(),
            event_hash: "event-a".into(),
            event_type: "VoteCast".into(),
            actor: "did:exo:alice".into(),
            tenant_id: "tenant-a".into(),
            decision_id: "decision-a".into(),
            timestamp_physical_ms: 1000,
            timestamp_logical: 0,
            entry_hash: "previous-entry-hash".into(),
        };
        let payload = serde_json::json!({
            "event": "vote_recorded",
            "decision_id": "decision-b",
            "voter": "did:exo:bob",
            "choice": "Approve",
        });
        let timestamp = exo_core::Timestamp::new(2000, 7);

        let first = build_audit_entry(
            Some(&previous),
            "VoteCast",
            "did:exo:bob",
            "tenant-b",
            "decision-b",
            timestamp,
            &payload,
        )
        .expect("audit entry");
        let second = build_audit_entry(
            Some(&previous),
            "VoteCast",
            "did:exo:bob",
            "tenant-b",
            "decision-b",
            timestamp,
            &payload,
        )
        .expect("audit entry");

        assert_eq!(first.sequence, 42);
        assert_eq!(first.prev_hash, previous.entry_hash);
        assert_eq!(
            first.event_hash,
            canonical_hash(&payload)
                .expect("canonical payload hash")
                .to_hex()
                .as_str()
        );
        assert_eq!(first.decision_id, "decision-b");
        assert_eq!(first.timestamp_physical_ms, 2000);
        assert_eq!(first.timestamp_logical, 7);
        assert_eq!(
            first.entry_hash, second.entry_hash,
            "same audit input must hash deterministically"
        );
    }

    #[test]
    fn first_audit_entry_uses_zero_previous_hash() {
        let payload = serde_json::json!({"event": "vote_recorded", "decision_id": "decision-1"});
        let timestamp = exo_core::Timestamp::new(3000, 0);

        let entry = build_audit_entry(
            None,
            "VoteCast",
            "did:exo:alice",
            "tenant-a",
            "decision-1",
            timestamp,
            &payload,
        )
        .expect("audit entry");

        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.prev_hash, Hash256::ZERO.to_string());
    }

    #[test]
    fn gateway_vote_audit_path_does_not_call_chrono_utc_now() {
        let source = include_str!("handlers.rs");
        let forbidden = ["chrono::Utc", "::now"].concat();
        assert!(
            !source.contains(&forbidden),
            "gateway vote audit path must use HLC timestamps, not wall-clock timestamps"
        );
    }

    #[test]
    fn gateway_vote_audit_path_does_not_create_hlc_clock_internally() {
        let source = include_str!("handlers.rs");
        let forbidden = ["HybridClock", "::new()"].concat();
        assert!(
            !source.contains(&forbidden),
            "gateway vote/audit path must use caller-supplied HLC timestamps"
        );
    }

    #[test]
    fn audit_entry_rejects_zero_timestamp() {
        let payload = serde_json::json!({"event": "vote_recorded", "decision_id": "decision-1"});
        let err = build_audit_entry(
            None,
            "VoteCast",
            "did:exo:alice",
            "tenant-a",
            "decision-1",
            exo_core::Timestamp::ZERO,
            &payload,
        )
        .expect_err("zero audit timestamp must be rejected");

        assert!(
            err.contains("timestamp"),
            "error should identify the invalid audit timestamp"
        );
    }

    #[test]
    fn vote_request_requires_caller_supplied_timestamp() {
        let mut without_timestamp = signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        );
        let without_timestamp_obj = without_timestamp.as_object_mut().expect("object");
        without_timestamp_obj.remove("timestamp_physical_ms");
        without_timestamp_obj.remove("timestamp_logical");
        assert!(
            serde_json::from_value::<VoteRequest>(without_timestamp).is_err(),
            "vote requests must not deserialize without explicit HLC timestamp metadata"
        );

        let with_timestamp = signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        );
        let request: VoteRequest =
            serde_json::from_value(with_timestamp).expect("timestamped vote request");

        assert_eq!(
            request
                .caller_supplied_timestamp()
                .expect("non-zero timestamp"),
            exo_core::Timestamp::new(7000, 2)
        );
    }

    #[test]
    fn vote_request_requires_signed_action_provenance_for_kernel_adjudication() {
        let without_provenance = serde_json::json!({
            "decision_id": "decision-1",
            "voter_did": "did:exo:alice",
            "affected_dids": ["did:exo:tenant-a"],
            "choice": "Approve",
            "actor_kind": "Human",
            "rationale": null,
            "timestamp_physical_ms": 7000,
            "timestamp_logical": 2
        });

        assert!(
            serde_json::from_value::<VoteRequest>(without_provenance).is_err(),
            "vote requests must carry signed action provenance before all-invariant kernel adjudication"
        );
    }

    #[test]
    fn vote_request_rejects_zero_timestamp() {
        let mut request_json = signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        );
        let request_obj = request_json.as_object_mut().expect("object");
        request_obj.insert("timestamp_physical_ms".to_owned(), serde_json::json!(0));
        request_obj.insert("timestamp_logical".to_owned(), serde_json::json!(0));
        let request: VoteRequest =
            serde_json::from_value(request_json).expect("request shape is valid");

        assert!(
            request.caller_supplied_timestamp().is_err(),
            "zero vote timestamp must be rejected"
        );
    }

    #[test]
    fn vote_request_does_not_require_caller_affected_dids_for_conflict_adjudication() {
        let mut without_affected_dids = signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &["did:exo:tenant-a"],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        );
        without_affected_dids
            .as_object_mut()
            .expect("object")
            .remove("affected_dids");
        let missing_affected_dids: VoteRequest =
            serde_json::from_value(without_affected_dids).expect("request shape is valid");
        assert!(
            missing_affected_dids.affected_dids.is_empty(),
            "request affected DIDs are optional because conflict context is stored on the decision"
        );

        let empty_affected_dids: VoteRequest = serde_json::from_value(signed_vote_request_json(
            "did:exo:alice",
            "decision-1",
            &[],
            VoteChoice::Approve,
            ActorKind::Human,
            exo_core::Timestamp::new(7000, 2),
        ))
        .expect("request shape is valid");
        assert!(
            empty_affected_dids.affected_dids.is_empty(),
            "empty request affected DIDs cannot make conflict adjudication vacuous"
        );
    }

    fn decision_for_affected_did_metadata_tests() -> DecisionObject {
        DecisionObject::new(decision_forum::decision_object::DecisionObjectInput {
            id: uuid::Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-777777777777").expect("valid UUID"),
            title: "Affected DID metadata test".to_owned(),
            class: decision_forum::decision_object::DecisionClass::Routine,
            constitutional_hash: Hash256::digest(b"affected-did-metadata-test"),
            created_at: Timestamp::new(7_000, 2),
        })
        .expect("valid decision")
    }

    #[test]
    fn trusted_decision_affected_dids_rejects_missing_metadata() {
        let decision = decision_for_affected_did_metadata_tests();

        let err = trusted_decision_affected_dids(&decision)
            .expect_err("missing stored affected DID metadata must fail closed");

        assert!(err.contains("affected_dids metadata is missing"));
    }

    #[test]
    fn trusted_decision_affected_dids_are_deduplicated_and_sorted() {
        let mut decision = decision_for_affected_did_metadata_tests();
        decision.metadata.insert(
            VOTE_DECISION_AFFECTED_DIDS_METADATA_KEY.to_owned(),
            serde_json::json!(["did:exo:tenant-z", "did:exo:tenant-a", "did:exo:tenant-z"])
                .to_string(),
        );

        let affected =
            trusted_decision_affected_dids(&decision).expect("stored affected DID metadata");
        let affected = affected.iter().map(Did::as_str).collect::<Vec<_>>();

        assert_eq!(affected, vec!["did:exo:tenant-a", "did:exo:tenant-z"]);
    }

    #[test]
    fn trusted_decision_affected_dids_block_conflict_even_when_request_context_is_unrelated() {
        let voter = Did::new("did:exo:alice").expect("valid DID");
        let mut decision = decision_for_affected_did_metadata_tests();
        decision.metadata.insert(
            VOTE_DECISION_AFFECTED_DIDS_METADATA_KEY.to_owned(),
            serde_json::json!(["did:exo:tenant-a"]).to_string(),
        );
        let request: VoteRequest = serde_json::from_value(signed_vote_request_json(
            voter.as_str(),
            "decision-1",
            &["did:exo:unrelated"],
            VoteChoice::Approve,
            ActorKind::Human,
            Timestamp::new(7_000, 2),
        ))
        .expect("signed vote request");
        assert_eq!(
            request.affected_dids,
            vec!["did:exo:unrelated".to_owned()],
            "test fixture must carry the attacker-selected request context"
        );

        let conflict_action = ConflictActionRequest {
            action_id: request.decision_id,
            actor_did: voter.clone(),
            affected_dids: trusted_decision_affected_dids(&decision)
                .expect("trusted affected DID metadata"),
            description: "Vote on decision-1".to_owned(),
        };
        let declarations = vec![exo_governance::conflict::ConflictDeclaration {
            declarant_did: voter.clone(),
            nature: "financial interest".to_owned(),
            related_dids: vec![Did::new("did:exo:tenant-a").expect("valid DID")],
            timestamp: Timestamp::new(6_000, 0),
        }];

        let conflicts = check_conflicts(&voter, &conflict_action, &declarations);

        assert!(
            check_and_block(&voter, &conflicts).is_err(),
            "trusted decision affected DIDs must preserve recusal enforcement"
        );
    }

    #[test]
    fn vote_handler_source_does_not_default_conflict_adjudication() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        assert!(
            !production.contains(
                ".load_conflict_declarations(&voter_did)\n        .await\n        .unwrap_or_default()"
            ),
            "vote handler must fail closed when the conflict register cannot be loaded"
        );
        assert!(
            production.contains(
                ".load_blocking_conflict_declarations_for_vote(&voter_did, &affected_dids)"
            ),
            "vote handler must use a scoped blocking-conflict lookup for recusal enforcement"
        );
        assert!(
            !production.contains("affected_dids: vec![]"),
            "vote handler must not adjudicate conflicts against an empty affected-DID set"
        );
        assert!(
            production.contains("check_and_block(&voter_did, &conflicts)"),
            "vote handler must use the enforcing conflict gate, not advisory-only recusal checks"
        );
    }

    #[test]
    fn vote_handler_derives_conflict_context_from_locked_decision_state() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// Check quorum post-vote")
            .next()
            .expect("vote handler pre-quorum block present");

        assert!(
            !vote_handler.contains("body.caller_supplied_affected_dids()"),
            "vote handler must not derive conflict affected DIDs from attacker-controlled request JSON"
        );

        let decision_load_index = vote_handler
            .find("let mut decision: DecisionObject")
            .expect("vote handler must load stored decision state");
        let trusted_affected_index = vote_handler
            .find("trusted_decision_affected_dids(&decision)")
            .expect("vote handler must derive affected DIDs from stored decision state");
        let conflict_index = vote_handler
            .find("check_conflicts(&voter_did")
            .expect("vote handler must run conflict checks");

        assert!(
            decision_load_index < trusted_affected_index && trusted_affected_index < conflict_index,
            "conflict checks must use affected DIDs derived from locked decision state"
        );
    }

    #[test]
    fn vote_handler_authenticates_session_actor_before_conflict_and_kernel_checks() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// Verify quorum precondition")
            .next()
            .expect("vote handler source end");
        let auth_index = vote_handler
            .find("require_authenticated_session_user_from_header")
            .expect("vote handler must authenticate a bearer session");
        let conflict_index = vote_handler
            .find("load_blocking_conflict_declarations_for_vote(&voter_did, &affected_dids)")
            .expect("vote handler must retain conflict lookup");
        let kernel_index = vote_handler
            .find("state.kernel.adjudicate")
            .expect("vote handler must retain kernel adjudication");
        let provenance_index = vote_handler
            .find("ctx.provenance = Some(provenance)")
            .expect("vote handler must attach action provenance before adjudication");

        assert!(
            auth_index < conflict_index && conflict_index < kernel_index,
            "vote handler must authenticate before conflict and kernel checks"
        );
        assert!(
            conflict_index < provenance_index && provenance_index < kernel_index,
            "vote handler must attach signed action provenance before kernel adjudication"
        );
        assert!(
            vote_handler.contains("if actor.did != voter_did"),
            "vote handler must reject body voter_did spoofing"
        );
    }

    #[test]
    fn vote_handler_updates_decision_under_row_lock_transaction() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// ── Health handler")
            .next()
            .expect("vote handler source end");

        assert!(
            vote_handler.contains("let mut tx = match db.begin().await"),
            "vote handler must update decisions inside a database transaction"
        );
        assert!(
            vote_handler.contains("FOR UPDATE"),
            "vote handler must lock the decision row before deserializing and mutating it"
        );
        assert!(
            vote_handler.contains(".fetch_optional(&mut *tx)"),
            "decision row read must happen through the transaction"
        );
        assert!(
            vote_handler.contains(".execute(&mut *tx)"),
            "decision update must happen through the transaction"
        );
        assert!(
            vote_handler.contains("tx.commit().await"),
            "vote handler must commit the transaction only after the update succeeds"
        );
        assert!(
            !vote_handler.contains(".fetch_optional(db)"),
            "vote handler must not read the mutable decision outside the transaction"
        );
        assert!(
            !vote_handler.contains(".execute(db)"),
            "vote handler must not update the mutable decision outside the transaction"
        );
    }

    #[test]
    fn vote_handler_writes_audit_in_vote_transaction_before_commit() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// ── Health handler")
            .next()
            .expect("vote handler source end");

        let update_index = vote_handler
            .find("UPDATE decisions SET payload = $1 WHERE id_hash = $2 AND tenant_id = $3")
            .expect("vote handler must persist the updated decision");
        let audit_index = vote_handler
            .find("write_audit_in_transaction(")
            .expect("vote handler must write the audit entry inside the vote transaction");
        let commit_index = vote_handler
            .find("tx.commit().await")
            .expect("vote handler must commit the vote transaction");
        let audit_call = &vote_handler[audit_index..commit_index];

        assert!(
            update_index < audit_index && audit_index < commit_index,
            "decision mutation and VoteCast audit entry must commit atomically"
        );
        assert!(
            audit_call.contains("&mut tx"),
            "VoteCast audit entry must be written through the existing vote transaction"
        );
        assert!(
            !vote_handler.contains("write_audit(\n        &state"),
            "vote handler must not commit the decision before a separate audit transaction"
        );
    }

    #[test]
    fn vote_handler_scopes_decision_mutation_to_authenticated_actor_tenant() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// ── Health handler")
            .next()
            .expect("vote handler source end");

        assert!(
            vote_handler.contains("require_authenticated_session_user_from_header(&headers)"),
            "vote handler must derive tenant scope from the authenticated session actor"
        );
        assert!(
            vote_handler
                .contains("FROM decisions WHERE id_hash = $1 AND tenant_id = $2 FOR UPDATE"),
            "vote handler must lock only the decision row in the actor tenant"
        );
        assert!(
            vote_handler.contains(".bind(&actor.tenant_id)"),
            "vote handler must bind the authenticated actor tenant to decision queries"
        );
        assert!(
            vote_handler.contains(
                "UPDATE decisions SET payload = $1 WHERE id_hash = $2 AND tenant_id = $3"
            ),
            "vote handler must update only the decision row in the actor tenant"
        );
    }

    #[test]
    fn vote_handler_quorum_precondition_uses_tenant_scoped_db_eligibility() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// Build the typed Vote")
            .next()
            .expect("vote handler quorum block present");
        let compact_vote_handler = vote_handler.split_whitespace().collect::<String>();

        assert!(
            compact_vote_handler.contains(
                "count_quorum_eligible_voters_in_transaction(&muttx,&actor.tenant_id,decision.class,)"
            ),
            "vote handler must derive quorum eligibility from the authenticated tenant and decision class"
        );
        assert!(
            vote_handler.contains("eligible.eligible_voters"),
            "vote handler must pass tenant-scoped total eligible voters to the quorum precondition"
        );
        assert!(
            vote_handler.contains("eligible.eligible_human_voters"),
            "vote handler must pass tenant-scoped human eligible voters to the quorum precondition"
        );
        assert!(
            !vote_handler.contains("state.registry_len().await"),
            "vote handler must not use the global in-memory DID registry as a quorum eligibility source"
        );
        assert!(
            !vote_handler.contains("let eligible_human_voters = eligible_voters"),
            "vote handler must not assume every registered DID is a human eligible voter"
        );
    }

    #[test]
    fn vote_handler_quorum_precondition_reuses_vote_transaction_connection() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// Build the typed Vote")
            .next()
            .expect("vote handler quorum block present");
        let compact_vote_handler = vote_handler.split_whitespace().collect::<String>();

        assert!(
            compact_vote_handler.contains(
                "crate::db::count_quorum_eligible_voters_in_transaction(&muttx,&actor.tenant_id,decision.class,)"
            ),
            "vote handler must count quorum eligibility on the already-held vote transaction connection"
        );
        assert!(
            !vote_handler.contains(".quorum_eligible_voter_counts("),
            "vote handler must not acquire a second pooled connection while holding the vote transaction"
        );
    }

    #[test]
    fn vote_handler_derives_actor_kind_from_authenticated_session_not_body() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// Add vote")
            .next()
            .expect("vote construction block present");

        assert!(
            production.contains("fn trusted_vote_actor_kind("),
            "gateway vote actor kind must be derived at the runtime adapter boundary"
        );
        assert!(
            vote_handler.contains("let actor_kind = match trusted_vote_actor_kind(&actor)")
                && vote_handler.contains("Ok(actor_kind) => actor_kind"),
            "vote handler must derive vote actor kind from the authenticated session profile"
        );
        assert!(
            vote_handler
                .contains("vote_action_provenance(&body, &voter_did, &affected_dids, &actor_kind)"),
            "vote provenance must bind the trusted actor kind, not the caller-supplied body field"
        );
        assert!(
            vote_handler.contains("actor_kind: actor_kind.clone()"),
            "stored vote actor kind must come from the authenticated session profile"
        );
        assert!(
            !vote_handler.contains("actor_kind: body.actor_kind"),
            "vote handler must not let clients self-attest human quorum status"
        );
    }

    #[test]
    fn vote_handler_checks_quorum_with_verified_human_voters() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// ── Health handler")
            .next()
            .expect("vote handler source end");

        assert!(
            vote_handler.contains("verified_human_voter_dids"),
            "vote handler must derive verified human voters from the authenticated tenant profile, not request JSON"
        );
        assert!(
            vote_handler.contains("check_quorum_with_verified_humans"),
            "vote handler must evaluate post-vote human quorum with the verified human voter set"
        );
    }

    #[test]
    fn vote_actor_kind_derivation_requires_active_session_user_profile() {
        let handler_source = include_str!("handlers.rs");
        let handler_production = handler_source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let server_source = include_str!("server.rs");

        assert!(
            server_source.contains("pub status: String"),
            "authenticated session profiles must carry user status to vote eligibility boundaries"
        );
        assert!(
            server_source.contains("status: user.status"),
            "session user resolution must preserve the status loaded from the users table"
        );
        assert!(
            handler_production.contains("actor.status == \"Active\""),
            "trusted vote actor-kind derivation must only classify active users as human voters"
        );
        assert!(
            handler_production.contains("\"voter is not eligible\""),
            "vote handler must fail closed when the authenticated user is not vote-eligible"
        );
    }

    #[test]
    fn trusted_vote_actor_kind_accepts_only_active_session_users() {
        let actor = AuthenticatedSessionUser {
            did: Did::new("did:exo:active-voter").expect("valid DID"),
            tenant_id: "tenant-a".to_owned(),
            status: "Active".to_owned(),
        };
        assert_eq!(
            trusted_vote_actor_kind(&actor).expect("active user is a human voter"),
            ActorKind::Human
        );

        let inactive_actor = AuthenticatedSessionUser {
            did: Did::new("did:exo:inactive-voter").expect("valid DID"),
            tenant_id: "tenant-a".to_owned(),
            status: "Suspended".to_owned(),
        };
        assert_eq!(
            trusted_vote_actor_kind(&inactive_actor).expect_err("inactive user must fail closed"),
            "voter is not eligible"
        );
    }

    #[test]
    fn vote_signature_hash_source_uses_canonical_cbor_not_debug_concat() {
        let source = include_str!("handlers.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        let vote_handler = production
            .split("pub async fn vote_handler")
            .nth(1)
            .expect("vote handler source present")
            .split("// ── Health handler")
            .next()
            .expect("vote handler source end");

        assert!(
            vote_handler.contains("vote_signature_hash("),
            "vote handler must route signature_hash construction through canonical helper"
        );
        assert!(
            !vote_handler.contains("format!(\"{}:{}:{:?}\""),
            "vote signature_hash must not use raw concat or Debug formatting"
        );
    }

    #[cfg(feature = "production-db")]
    #[tokio::test]
    async fn vote_audit_write_is_read_by_audit_route_from_migrated_schema() {
        use std::sync::{Arc, RwLock};

        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use exo_identity::registry::LocalDidRegistry;
        use sqlx::postgres::PgPoolOptions;
        use tower::ServiceExt;

        let url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return,
        };
        let pool = match PgPoolOptions::new().max_connections(1).connect(&url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations");
        let decision_id = "decision-r4-audit-route";
        let reader = "did:exo:r4-audit-reader";
        let token = "r4-audit-reader-token";
        const ACTIVE_TEST_SESSION_EXPIRES_AT_MS: i64 = 4_102_444_800_000;
        sqlx::query("DELETE FROM audit_entries WHERE decision_id = $1")
            .bind(decision_id)
            .execute(&pool)
            .await
            .expect("clean audit entries");
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .expect("clean session");
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .expect("clean reader user");
        crate::db::insert_user(
            &pool,
            reader,
            "Audit Reader",
            "r4-audit-reader@example.invalid",
            &serde_json::json!(["reader"]),
            "tenant-r4",
            1_000,
            "Active",
            "Complete",
            "redacted-test-hash",
            "redacted-test-salt",
            false,
        )
        .await
        .expect("insert reader user");
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(reader)
        .bind(1_000_i64)
        .bind(ACTIVE_TEST_SESSION_EXPIRES_AT_MS)
        .execute(&pool)
        .await
        .expect("insert reader session");

        let state = AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        );
        let voter = "did:exo:r4-voter";
        let payload = serde_json::json!({
            "event": "vote_recorded",
            "decision_id": decision_id,
            "voter": voter,
            "choice": "Approve",
        });

        write_audit(
            &state,
            "VoteCast",
            voter,
            "tenant-r4",
            decision_id,
            exo_core::Timestamp::new(9000, 0),
            &payload,
        )
        .await
        .expect("first audit write");
        write_audit(
            &state,
            "VoteCast",
            voter,
            "tenant-r4",
            decision_id,
            exo_core::Timestamp::new(9001, 0),
            &payload,
        )
        .await
        .expect("second audit write");

        let app = crate::server::build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/audit/{decision_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-exo-auth-observed-at-ms", "15000")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let entries = body["audit_entries"].as_array().expect("entries array");

        assert_eq!(entries.len(), 2);
        let first_sequence = entries[0]["sequence"].as_i64().expect("first sequence");
        let second_sequence = entries[1]["sequence"].as_i64().expect("second sequence");
        assert_eq!(second_sequence, first_sequence + 1);
        assert_eq!(entries[0]["decision_id"], decision_id);
        assert_eq!(entries[1]["decision_id"], decision_id);
        assert_eq!(entries[0]["tenant_id"], "tenant-r4");
        assert_eq!(entries[1]["tenant_id"], "tenant-r4");

        sqlx::query("DELETE FROM audit_entries WHERE decision_id = $1")
            .bind(decision_id)
            .execute(&pool)
            .await
            .expect("cleanup audit entries");
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .expect("cleanup session");
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .expect("cleanup reader user");
    }

    // Violation 1: must_recuse returns true for financial conflict
    #[test]
    fn financial_conflict_blocks_vote() {
        use exo_core::{Did, Timestamp};
        use exo_governance::conflict::{
            ActionRequest, ConflictDeclaration, check_conflicts, must_recuse,
        };
        let voter = Did::new("did:exo:alice").expect("valid did");
        let decl = ConflictDeclaration {
            declarant_did: voter.clone(),
            nature: "financial interest".into(),
            related_dids: vec![Did::new("did:exo:bob").expect("valid did")],
            timestamp: Timestamp::new(1000, 0),
        };
        let action = ActionRequest {
            action_id: "d1".into(),
            actor_did: voter.clone(),
            affected_dids: vec![Did::new("did:exo:bob").expect("valid did")],
            description: "vote".into(),
        };
        let conflicts = check_conflicts(&voter, &action, &[decl]);
        assert!(must_recuse(&conflicts));
    }
}
