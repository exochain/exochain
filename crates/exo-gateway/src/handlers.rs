//! HTTP route handlers — axum handler functions for all gateway endpoints.
//!
//! CONSTITUTIONAL REQUIREMENTS (do not remove):
//!   1. Vote handler MUST call `check_conflicts` + `must_recuse` (ConflictAdjudication)
//!   2. Vote handler MUST call `Kernel::adjudicate` and gate on `Verdict::Permitted` (TNC-01)
//!   3. `write_audit` MUST use `ciborium::into_writer` before blake3, not serde_json (TransparencyAccountability)

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use decision_forum::{
    decision_object::{ActorKind, DecisionObject, Vote, VoteChoice},
    quorum::{QuorumCheckResult, QuorumRegistry, check_quorum, verify_quorum_precondition},
};
use exo_core::{Timestamp, types::Hash256};
use exo_gatekeeper::{
    kernel::{ActionRequest as GatekeeperActionRequest, Verdict},
    types::{Permission, PermissionSet},
};
use exo_governance::conflict::{
    ActionRequest as ConflictActionRequest, check_conflicts, must_recuse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

use crate::server::AppState;

// ── Violation 3 fix: CBOR canonical hashing ──────────────────────────────

/// Serialize `payload` using canonical CBOR then hash with blake3.
/// This is deterministic across all deployments regardless of field insertion order.
/// NEVER replace with serde_json::to_vec — JSON key ordering is non-deterministic.
fn canonical_cbor_hash(payload: &impl Serialize) -> Result<blake3::Hash, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)
        .map_err(|e| format!("CBOR serialization failed: {e}"))?;
    Ok(blake3::hash(&buf))
}

fn canonical_hash(payload: &Value) -> Result<blake3::Hash, String> {
    canonical_cbor_hash(payload)
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
    sqlx::query("LOCK TABLE audit_entries IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    let last = sqlx::query_as::<_, crate::db::AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash
         FROM audit_entries ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
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
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ── Vote handler (decision-forum integration) ─────────────────────────────

/// Request body for casting a vote on a governance decision.
#[derive(Deserialize)]
pub struct VoteRequest {
    pub decision_id: String,
    pub voter_did: String,
    pub choice: VoteChoice,
    pub actor_kind: ActorKind,
    pub rationale: Option<String>,
    pub timestamp_physical_ms: u64,
    pub timestamp_logical: u32,
}

impl VoteRequest {
    fn caller_supplied_timestamp(&self) -> Result<Timestamp, String> {
        let timestamp = Timestamp::new(self.timestamp_physical_ms, self.timestamp_logical);
        if timestamp == Timestamp::ZERO {
            return Err("vote timestamp must be caller-supplied and non-zero".to_owned());
        }
        Ok(timestamp)
    }
}

/// Handle a vote submission with conflict-of-interest and authority chain checks.
pub async fn vote_handler(
    State(state): State<AppState>,
    Json(body): Json<VoteRequest>,
) -> impl IntoResponse {
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

    // ── VIOLATION 1 FIX: ConflictAdjudication ───────────────────────────
    // Check if voter has a declared conflict of interest on this decision.
    let declarations = state
        .load_conflict_declarations(&voter_did)
        .await
        .unwrap_or_default();
    let conflict_action = ConflictActionRequest {
        action_id: body.decision_id.clone(),
        actor_did: voter_did.clone(),
        affected_dids: vec![],
        description: format!("Vote on {}", body.decision_id),
    };
    let conflicts = check_conflicts(&voter_did, &conflict_action, &declarations);
    if must_recuse(&conflicts) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "must recuse due to conflict of interest"})),
        )
            .into_response();
    }

    // ── VIOLATION 2 FIX: TNC-01 Authority Chain / Governor Clearance ────
    let gk_action = GatekeeperActionRequest {
        actor: voter_did.clone(),
        action: "Vote".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("vote")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    let ctx = state.build_adjudication_context(&voter_did).await;
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

    // Require DB pool — return 503 if not configured.
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Load and deserialize DecisionObject from DB.
    let row = sqlx::query("SELECT tenant_id, payload FROM decisions WHERE id_hash = $1")
        .bind(&body.decision_id)
        .fetch_optional(db)
        .await;
    let (tenant_id, payload_val): (String, Value) = match row {
        Ok(Some(r)) => {
            let tenant_id = match r.try_get::<String, _>("tenant_id") {
                Ok(t) => t,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };
            let payload = match r.try_get::<Value, _>("payload") {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let mut decision: DecisionObject = match serde_json::from_value(payload_val) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to deserialize decision: {e}")})),
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

    // Verify quorum precondition (TNC-07): enough eligible voters must exist
    // before accepting the vote. This gateway registry currently stores
    // voter DIDs, so its cardinality is both the total and human-eligible
    // count supplied to the decision-forum precondition.
    let registry = QuorumRegistry::with_defaults();
    let eligible_voters = state
        .registry
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let eligible_human_voters = eligible_voters;
    match verify_quorum_precondition(
        &registry,
        decision.class,
        eligible_voters,
        eligible_human_voters,
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
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
    let sig_input = format!("{}:{}:{:?}", body.voter_did, body.decision_id, body.choice);
    let signature_hash = Hash256::digest(sig_input.as_bytes());
    let vote = Vote {
        voter_did: voter_did.clone(),
        choice: body.choice,
        actor_kind: body.actor_kind,
        timestamp,
        signature_hash,
    };

    // Add vote — rejects duplicates (TNC-07 voter independence).
    if let Err(e) = decision.add_vote(vote) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Check quorum post-vote to include status in response.
    let quorum_result = match check_quorum(&registry, &decision) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Serialize updated DecisionObject back to JSON for DB persistence.
    let updated_payload = match serde_json::to_value(&decision) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialization failed: {e}")})),
            )
                .into_response();
        }
    };

    // Persist updated decision.
    if let Err(e) = sqlx::query("UPDATE decisions SET payload = $1 WHERE id_hash = $2")
        .bind(&updated_payload)
        .bind(&body.decision_id)
        .execute(db)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to persist vote: {e}")})),
        )
            .into_response();
    }

    // ── VIOLATION 3 FIX: CBOR canonical audit hash ──────────────────────
    let audit_payload = serde_json::json!({
        "event": "VoteCast",
        "decision_id": body.decision_id.as_str(),
        "tenant_id": tenant_id.as_str(),
        "voter": body.voter_did.as_str(),
        "choice": body.choice,
        "timestamp_physical_ms": timestamp.physical_ms,
        "timestamp_logical": timestamp.logical,
    });
    if let Err(e) = write_audit(
        &state,
        "VoteCast",
        &body.voter_did,
        &tenant_id,
        &body.decision_id,
        timestamp,
        &audit_payload,
    )
    .await
    {
        tracing::error!("audit write failed for voter {}: {e}", body.voter_did);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("audit write failed: {e}")})),
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
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"status": "degraded", "error": e.to_string()})),
            )
                .into_response(),
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
        let without_timestamp = serde_json::json!({
            "decision_id": "decision-1",
            "voter_did": "did:exo:alice",
            "choice": "Approve",
            "actor_kind": "Human",
            "rationale": null
        });
        assert!(
            serde_json::from_value::<VoteRequest>(without_timestamp).is_err(),
            "vote requests must not deserialize without explicit HLC timestamp metadata"
        );

        let with_timestamp = serde_json::json!({
            "decision_id": "decision-1",
            "voter_did": "did:exo:alice",
            "choice": "Approve",
            "actor_kind": "Human",
            "rationale": null,
            "timestamp_physical_ms": 7000,
            "timestamp_logical": 2
        });
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
    fn vote_request_rejects_zero_timestamp() {
        let request: VoteRequest = serde_json::from_value(serde_json::json!({
            "decision_id": "decision-1",
            "voter_did": "did:exo:alice",
            "choice": "Approve",
            "actor_kind": "Human",
            "rationale": null,
            "timestamp_physical_ms": 0,
            "timestamp_logical": 0
        }))
        .expect("request shape is valid");

        assert!(
            request.caller_supplied_timestamp().is_err(),
            "zero vote timestamp must be rejected"
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
        sqlx::query("DELETE FROM audit_entries")
            .execute(&pool)
            .await
            .expect("clean audit entries");

        let state = AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        );
        let decision_id = "decision-r4-audit-route";
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
        assert_eq!(entries[0]["sequence"], 1);
        assert_eq!(entries[1]["sequence"], 2);
        assert_eq!(entries[0]["decision_id"], decision_id);
        assert_eq!(entries[1]["prev_hash"], entries[0]["entry_hash"]);
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
