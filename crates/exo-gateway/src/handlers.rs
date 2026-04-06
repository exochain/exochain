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
use exo_core::{hlc::HybridClock, types::Hash256};
use exo_gatekeeper::{
    kernel::{ActionRequest as GatekeeperActionRequest, Verdict},
    types::{Permission, PermissionSet},
};
use exo_governance::conflict::{
    ActionRequest as ConflictActionRequest, check_conflicts, must_recuse,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;

use crate::server::AppState;

// ── Violation 3 fix: CBOR canonical hashing ──────────────────────────────

/// Serialize `payload` using canonical CBOR then hash with blake3.
/// This is deterministic across all deployments regardless of field insertion order.
/// NEVER replace with serde_json::to_vec — JSON key ordering is non-deterministic.
fn canonical_hash(payload: &Value) -> Result<blake3::Hash, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)
        .map_err(|e| format!("CBOR serialization failed: {e}"))?;
    Ok(blake3::hash(&buf))
}

/// Write an audit entry using CBOR-hashed event payload.
async fn write_audit(
    state: &AppState,
    event_type: &str,
    actor: &str,
    payload: &Value,
) -> Result<(), String> {
    let db = state.require_db().map_err(|e| e.to_string())?;
    let event_hash = canonical_hash(payload)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO audit_entries (event_type, actor, event_hash, payload, created_at_ms) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(event_type)
    .bind(actor)
    .bind(event_hash.to_hex().as_str())
    .bind(payload)
    .bind(now_ms)
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;
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
    let row = sqlx::query("SELECT payload FROM decisions WHERE id_hash = $1")
        .bind(&body.decision_id)
        .fetch_optional(db)
        .await;
    let payload_val: Value = match row {
        Ok(Some(r)) => match r.try_get::<Value, _>("payload") {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        },
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
    // before accepting the vote. Use the registered DID count as the eligible
    // voter count since the gateway does not maintain a separate voter registry.
    let registry = QuorumRegistry::with_defaults();
    let eligible_voters = state
        .registry
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    match verify_quorum_precondition(&registry, decision.class, eligible_voters) {
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

    // Build the typed Vote using HLC for deterministic timestamp (AGENTS.md §1).
    let mut clock = HybridClock::new();
    let timestamp = clock.now();
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
        "event": "vote_recorded",
        "decision_id": body.decision_id,
        "voter": body.voter_did,
        "choice": body.choice,
    });
    if let Err(e) = write_audit(&state, "vote_recorded", &body.voter_did, &audit_payload).await {
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
