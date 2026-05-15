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

//! PostgreSQL persistence layer for EXOCHAIN decision.forum.
//!
//! Replaces in-memory AppState Vecs/HashMaps with real database operations.
//! Complex governance objects (DecisionObject, Delegation) are stored as
//! JSONB payloads with indexed scalar columns for efficient queries.

use std::time::Duration;

use decision_forum::decision_object::DecisionClass;
use exo_identity::did::DidDocument;
use serde_json::Value as JsonValue;
use sqlx::{
    Row,
    postgres::{PgPool, PgPoolOptions},
};
use thiserror::Error;

pub const MAX_DB_LIST_ROWS: i64 = 1_000;
const DB_POOL_ACQUIRE_TIMEOUT_SECS: u64 = 5;
const LOCATION_CONSENT_SCOPE: &str = "location";

#[derive(Debug, Error)]
pub enum DbInitError {
    #[error("failed to connect to PostgreSQL")]
    Connect {
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to run database migrations")]
    Migrate {
        #[source]
        source: sqlx::migrate::MigrateError,
    },
}

#[derive(Debug, Error)]
pub enum DecisionUpdateError {
    #[error("decision update matched no rows for tenant_id {tenant_id} and id_hash {id_hash}")]
    MissingDecision { tenant_id: String, id_hash: String },
    #[error("failed to update decision row")]
    Query {
        #[source]
        source: sqlx::Error,
    },
}

#[derive(Debug, Error)]
pub enum DecisionCreateError {
    #[error("decision already exists for tenant_id {tenant_id} and id_hash {id_hash}")]
    AlreadyExists { tenant_id: String, id_hash: String },
    #[error("failed to create decision row")]
    Query {
        #[source]
        source: sqlx::Error,
    },
}

#[derive(Debug, Error)]
pub enum DidDocumentPersistenceError {
    #[error("DID document timestamp is out of database range for field {field}: {value}")]
    TimestampOutOfRange {
        did: String,
        field: &'static str,
        value: u64,
    },
    #[error("failed to serialize DID document")]
    Serialize {
        did: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to deserialize persisted DID document")]
    Deserialize {
        did: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("persisted DID document row key does not match payload id")]
    DocumentDidMismatch {
        row_did: String,
        document_did: String,
    },
    #[error("DID document persistence query failed")]
    Query {
        #[source]
        source: sqlx::Error,
    },
}

#[derive(Debug, Error)]
pub enum GatewayIdentityErasureError {
    #[error("identity erasure timestamp must be positive: {erased_at_ms}")]
    InvalidTimestamp { erased_at_ms: i64 },
    #[error("gateway identity erasure query failed")]
    Query {
        #[source]
        source: sqlx::Error,
    },
}

#[derive(Debug, Error)]
pub enum ScanReceiptInsertError {
    #[error("scan receipt location requires active location consent")]
    LocationConsentRequired,
    #[error("scan receipt insert query failed")]
    Query {
        #[source]
        source: sqlx::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GatewayIdentityErasureSummary {
    pub did_documents_tombstoned: u64,
    pub users_deleted: u64,
    pub agents_deleted: u64,
    pub sessions_deleted: u64,
    pub identity_scores_deleted: u64,
    pub enrollment_log_deleted: u64,
    pub livesafe_identities_deleted: u64,
    pub scan_receipts_deleted: u64,
    pub consent_anchors_deleted: u64,
    pub trustee_shards_deleted: u64,
    pub agent_roles_deleted: u64,
    pub consent_records_deleted: u64,
    pub authority_chains_deleted: u64,
    pub delegations_deleted: u64,
    pub layout_templates_deleted: u64,
    pub feedback_issues_deleted: u64,
    pub conflict_declarations_deleted: u64,
}

// ---------------------------------------------------------------------------
// Pool initialization
// ---------------------------------------------------------------------------

/// Create a connection pool and run migrations.
pub async fn init_pool(database_url: &str) -> Result<PgPool, DbInitError> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        // SQLx 0.8 bounds both waiting for a pooled connection and opening a
        // new connection through acquire_timeout.
        .acquire_timeout(Duration::from_secs(DB_POOL_ACQUIRE_TIMEOUT_SECS))
        .connect(database_url)
        .await
        .map_err(|source| DbInitError::Connect { source })?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|source| DbInitError::Migrate { source })?;

    tracing::info!("PostgreSQL connection pool ready and migrations applied");
    Ok(pool)
}

// ---------------------------------------------------------------------------
// HLC counter (atomic increment)
// ---------------------------------------------------------------------------

/// Atomically increment and return the next HLC counter value.
pub async fn next_hlc(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("UPDATE hlc_state SET counter = counter + 1 RETURNING counter")
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("counter"))
}

// ---------------------------------------------------------------------------
// DID documents
// ---------------------------------------------------------------------------

fn timestamp_ms_to_i64(
    did: &str,
    field: &'static str,
    value: u64,
) -> Result<i64, DidDocumentPersistenceError> {
    i64::try_from(value).map_err(|_| DidDocumentPersistenceError::TimestampOutOfRange {
        did: did.to_owned(),
        field,
        value,
    })
}

pub async fn insert_did_document(
    pool: &PgPool,
    doc: &DidDocument,
) -> Result<bool, DidDocumentPersistenceError> {
    let did = doc.id.as_str();
    let document =
        serde_json::to_value(doc).map_err(|source| DidDocumentPersistenceError::Serialize {
            did: did.to_owned(),
            source,
        })?;
    let created_at_ms = timestamp_ms_to_i64(did, "created", doc.created.physical_ms)?;
    let updated_at_ms = timestamp_ms_to_i64(did, "updated", doc.updated.physical_ms)?;

    let result = sqlx::query(
        "INSERT INTO did_documents (did, document, created_at_ms, updated_at_ms, revoked) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (did) DO NOTHING",
    )
    .bind(did)
    .bind(document)
    .bind(created_at_ms)
    .bind(updated_at_ms)
    .bind(doc.revoked)
    .execute(pool)
    .await
    .map_err(|source| DidDocumentPersistenceError::Query { source })?;

    Ok(result.rows_affected() > 0)
}

pub async fn find_did_document(
    pool: &PgPool,
    did: &str,
) -> Result<Option<DidDocument>, DidDocumentPersistenceError> {
    let row = sqlx::query(
        "SELECT document \
         FROM did_documents \
         WHERE did = $1 AND revoked = false",
    )
    .bind(did)
    .fetch_optional(pool)
    .await
    .map_err(|source| DidDocumentPersistenceError::Query { source })?;

    let Some(row) = row else {
        return Ok(None);
    };
    let document = row.get::<JsonValue, _>("document");
    let doc = serde_json::from_value::<DidDocument>(document).map_err(|source| {
        DidDocumentPersistenceError::Deserialize {
            did: did.to_owned(),
            source,
        }
    })?;
    if doc.id.as_str() != did {
        return Err(DidDocumentPersistenceError::DocumentDidMismatch {
            row_did: did.to_owned(),
            document_did: doc.id.as_str().to_owned(),
        });
    }
    Ok(Some(doc))
}

pub async fn list_did_document_ids(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT did \
         FROM did_documents \
         WHERE revoked = false \
         ORDER BY did \
         LIMIT $1",
    )
    .bind(MAX_DB_LIST_ROWS)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| row.get::<String, _>("did"))
        .collect())
}

pub async fn erase_gateway_identity_records(
    pool: &PgPool,
    did: &str,
    erased_at_ms: i64,
) -> Result<GatewayIdentityErasureSummary, GatewayIdentityErasureError> {
    if erased_at_ms <= 0 {
        return Err(GatewayIdentityErasureError::InvalidTimestamp { erased_at_ms });
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?;
    let tombstone = serde_json::json!({
        "schema": "exo.gateway.did_document_tombstone.v1",
        "erased": true
    });

    let did_documents_tombstoned = sqlx::query(
        "UPDATE did_documents \
         SET document = $2, updated_at_ms = $3, revoked = true, erased_at_ms = $3 \
         WHERE did = $1",
    )
    .bind(did)
    .bind(tombstone)
    .bind(erased_at_ms)
    .execute(&mut *tx)
    .await
    .map_err(|source| GatewayIdentityErasureError::Query { source })?
    .rows_affected();

    let sessions_deleted = sqlx::query("DELETE FROM sessions WHERE actor_did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let users_deleted = sqlx::query("DELETE FROM users WHERE did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let agents_deleted = sqlx::query("DELETE FROM agents WHERE did = $1 OR owner_did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let identity_scores_deleted = sqlx::query("DELETE FROM identity_scores WHERE did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let enrollment_log_deleted = sqlx::query("DELETE FROM enrollment_log WHERE did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let livesafe_identities_deleted = sqlx::query("DELETE FROM livesafe_identities WHERE did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let scan_receipts_deleted =
        sqlx::query("DELETE FROM scan_receipts WHERE subscriber_did = $1 OR responder_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let consent_anchors_deleted =
        sqlx::query("DELETE FROM consent_anchors WHERE subscriber_did = $1 OR provider_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let trustee_shards_deleted = sqlx::query(
        "DELETE FROM trustee_shard_status WHERE subscriber_did = $1 OR trustee_did = $1",
    )
    .bind(did)
    .execute(&mut *tx)
    .await
    .map_err(|source| GatewayIdentityErasureError::Query { source })?
    .rows_affected();

    let agent_roles_deleted =
        sqlx::query("DELETE FROM agent_roles WHERE agent_did = $1 OR granted_by = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let consent_records_deleted =
        sqlx::query("DELETE FROM consent_records WHERE subject_did = $1 OR actor_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let authority_chains_deleted = sqlx::query("DELETE FROM authority_chains WHERE actor_did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let delegations_deleted =
        sqlx::query("DELETE FROM delegations WHERE delegator = $1 OR delegatee = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let layout_templates_deleted = sqlx::query("DELETE FROM layout_templates WHERE user_did = $1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?
        .rows_affected();

    let feedback_issues_deleted =
        sqlx::query("DELETE FROM feedback_issues WHERE reporter_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|source| GatewayIdentityErasureError::Query { source })?
            .rows_affected();

    let conflict_declarations_deleted = sqlx::query(
        "DELETE FROM conflict_declarations \
         WHERE declarant_did = $1 OR related_dids @> jsonb_build_array($1::text)",
    )
    .bind(did)
    .execute(&mut *tx)
    .await
    .map_err(|source| GatewayIdentityErasureError::Query { source })?
    .rows_affected();

    tx.commit()
        .await
        .map_err(|source| GatewayIdentityErasureError::Query { source })?;

    Ok(GatewayIdentityErasureSummary {
        did_documents_tombstoned,
        users_deleted,
        agents_deleted,
        sessions_deleted,
        identity_scores_deleted,
        enrollment_log_deleted,
        livesafe_identities_deleted,
        scan_receipts_deleted,
        consent_anchors_deleted,
        trustee_shards_deleted,
        agent_roles_deleted,
        consent_records_deleted,
        authority_chains_deleted,
        delegations_deleted,
        layout_templates_deleted,
        feedback_issues_deleted,
        conflict_declarations_deleted,
    })
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Insert a new user record, ignoring conflicts on duplicate DID.
#[allow(clippy::too_many_arguments)]
pub async fn insert_user(
    pool: &PgPool,
    did: &str,
    display_name: &str,
    email: &str,
    roles: &JsonValue,
    tenant_id: &str,
    created_at: i64,
    status: &str,
    pace_status: &str,
    password_hash: &str,
    salt: &str,
    mfa_enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (did) DO NOTHING"
    )
    .bind(did).bind(display_name).bind(email).bind(roles).bind(tenant_id)
    .bind(created_at).bind(status).bind(pace_status).bind(password_hash)
    .bind(salt).bind(mfa_enabled)
    .execute(pool).await?;
    Ok(())
}

/// Look up a user by email address, returning `None` if not found.
pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<PublicUserRow>, sqlx::Error> {
    sqlx::query_as::<_, PublicUserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, mfa_enabled FROM users WHERE email = $1"
    ).bind(email).fetch_optional(pool).await
}

/// Look up a user by DID, returning `None` if not found.
pub async fn find_user_by_did(
    pool: &PgPool,
    did: &str,
) -> Result<Option<PublicUserRow>, sqlx::Error> {
    sqlx::query_as::<_, PublicUserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, mfa_enabled FROM users WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

/// List users for a tenant ordered by creation time.
pub async fn list_users_db(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Vec<PublicUserRow>, sqlx::Error> {
    sqlx::query_as::<_, PublicUserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, mfa_enabled FROM users WHERE tenant_id = $1 ORDER BY created_at LIMIT $2"
    ).bind(tenant_id).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Update a user's PACE enrollment status.
pub async fn update_user_pace(
    pool: &PgPool,
    did: &str,
    pace_status: &str,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query("UPDATE users SET pace_status = $1 WHERE did = $2")
        .bind(pace_status)
        .bind(did)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Check whether a user with the given email exists.
pub async fn user_exists_by_email(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await?
        .is_some())
}

/// Return the total number of registered users.
pub async fn count_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) as cnt FROM users")
        .fetch_one(pool)
        .await?
        .get::<i64, _>("cnt"))
}

/// Non-secret user projection for list APIs and administrative directories.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PublicUserRow {
    pub did: String,
    pub display_name: String,
    pub email: String,
    pub roles: JsonValue,
    pub tenant_id: String,
    pub created_at: i64,
    pub status: String,
    pub pace_status: String,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumEligibilityCounts {
    pub eligible_voters: usize,
    pub eligible_human_voters: usize,
}

fn decision_class_rank(class: DecisionClass) -> i32 {
    match class {
        DecisionClass::Routine => 0,
        DecisionClass::Operational => 1,
        DecisionClass::Strategic => 2,
        DecisionClass::Constitutional => 3,
    }
}

fn count_result_to_usize(label: &'static str, value: i64) -> Result<usize, sqlx::Error> {
    usize::try_from(value)
        .map_err(|_| sqlx::Error::Protocol(format!("{label} returned invalid count {value}")))
}

/// Count quorum-eligible voters for a tenant and decision class.
pub async fn count_quorum_eligible_voters(
    pool: &PgPool,
    tenant_id: &str,
    decision_class: DecisionClass,
) -> Result<QuorumEligibilityCounts, sqlx::Error> {
    let active_human_users = count_result_to_usize(
        "active_human_users",
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND status = 'Active'",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?,
    )?;
    let active_delegated_agents = count_result_to_usize(
        "active_delegated_agents",
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM agents
            WHERE tenant_id = $1
              AND status = 'Active'
              AND delegation_id IS NOT NULL
              AND CASE max_decision_class
                  WHEN 'Routine' THEN 0
                  WHEN 'Operational' THEN 1
                  WHEN 'Strategic' THEN 2
                  WHEN 'Constitutional' THEN 3
                  ELSE -1
              END >= $2
            "#,
        )
        .bind(tenant_id)
        .bind(decision_class_rank(decision_class))
        .fetch_one(pool)
        .await?,
    )?;
    let eligible_voters = active_human_users
        .checked_add(active_delegated_agents)
        .ok_or_else(|| sqlx::Error::Protocol("quorum eligible voter count overflowed".into()))?;

    Ok(QuorumEligibilityCounts {
        eligible_voters,
        eligible_human_voters: active_human_users,
    })
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

/// Insert a new agent record, ignoring conflicts on duplicate DID.
#[allow(clippy::too_many_arguments)]
pub async fn insert_agent(
    pool: &PgPool,
    did: &str,
    agent_name: &str,
    agent_type: &str,
    owner_did: &str,
    tenant_id: &str,
    capabilities: &JsonValue,
    trust_tier: &str,
    trust_score: i32,
    delegation_id: Option<&str>,
    pace_status: &str,
    created_at: i64,
    status: &str,
    max_decision_class: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agents (did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (did) DO NOTHING"
    )
    .bind(did).bind(agent_name).bind(agent_type).bind(owner_did).bind(tenant_id)
    .bind(capabilities).bind(trust_tier).bind(trust_score).bind(delegation_id)
    .bind(pace_status).bind(created_at).bind(status).bind(max_decision_class)
    .execute(pool).await?;
    Ok(())
}

/// Look up an agent by DID, returning `None` if not found.
pub async fn find_agent_by_did(
    pool: &PgPool,
    did: &str,
    tenant_id: &str,
) -> Result<Option<AgentRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentRow>(
        "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE did = $1 AND tenant_id = $2"
    ).bind(did).bind(tenant_id).fetch_optional(pool).await
}

/// List agents for a tenant, ordered by creation time.
pub async fn list_agents_db(pool: &PgPool, tenant_id: &str) -> Result<Vec<AgentRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentRow>(
        "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE tenant_id = $1 ORDER BY created_at LIMIT $2"
    ).bind(tenant_id).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Update an agent's PACE enrollment status.
pub async fn update_agent_pace(
    pool: &PgPool,
    did: &str,
    pace_status: &str,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query("UPDATE agents SET pace_status = $1 WHERE did = $2")
        .bind(pace_status)
        .bind(did)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Row representation of an agent record from the `agents` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRow {
    pub did: String,
    pub agent_name: String,
    pub agent_type: String,
    pub owner_did: String,
    pub tenant_id: String,
    pub capabilities: JsonValue,
    pub trust_tier: String,
    pub trust_score: i32,
    pub delegation_id: Option<String>,
    pub pace_status: String,
    pub created_at: i64,
    pub status: String,
    pub max_decision_class: String,
}

// ---------------------------------------------------------------------------
// Decisions (JSONB payload)
// ---------------------------------------------------------------------------

/// Insert or update a decision record (upserts on `id_hash` conflict).
#[allow(clippy::too_many_arguments)]
pub async fn insert_decision(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
    status: &str,
    title: &str,
    decision_class: &str,
    author: &str,
    created_at_ms: i64,
    constitution_version: &str,
    payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO decisions (id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (tenant_id, id_hash) DO UPDATE SET status = $3, payload = $9"
    )
    .bind(id_hash).bind(tenant_id).bind(status).bind(title).bind(decision_class)
    .bind(author).bind(created_at_ms).bind(constitution_version).bind(payload)
    .execute(pool).await?;
    Ok(())
}

/// Create a new decision row without mutating an existing id.
#[allow(clippy::too_many_arguments)]
pub async fn create_decision(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
    status: &str,
    title: &str,
    decision_class: &str,
    author: &str,
    created_at_ms: i64,
    constitution_version: &str,
    payload: &JsonValue,
) -> Result<(), DecisionCreateError> {
    let result = sqlx::query(
        "INSERT INTO decisions (id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (tenant_id, id_hash) DO NOTHING"
    )
    .bind(id_hash)
    .bind(tenant_id)
    .bind(status)
    .bind(title)
    .bind(decision_class)
    .bind(author)
    .bind(created_at_ms)
    .bind(constitution_version)
    .bind(payload)
    .execute(pool)
    .await
    .map_err(|source| DecisionCreateError::Query { source })?;
    if result.rows_affected() == 0 {
        return Err(DecisionCreateError::AlreadyExists {
            tenant_id: tenant_id.to_owned(),
            id_hash: id_hash.to_owned(),
        });
    }
    Ok(())
}

/// Alias for insert_decision — the INSERT already has ON CONFLICT DO UPDATE.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_decision(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
    status: &str,
    title: &str,
    decision_class: &str,
    author: &str,
    created_at_ms: i64,
    constitution_version: &str,
    payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    insert_decision(
        pool,
        id_hash,
        tenant_id,
        status,
        title,
        decision_class,
        author,
        created_at_ms,
        constitution_version,
        payload,
    )
    .await
}

/// Look up a decision by its content hash, returning `None` if not found.
pub async fn find_decision(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
) -> Result<Option<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions WHERE id_hash = $1 AND tenant_id = $2"
    ).bind(id_hash).bind(tenant_id).fetch_optional(pool).await
}

/// List decisions for a tenant ordered by creation timestamp.
pub async fn list_decisions_db(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Vec<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions WHERE tenant_id = $1 ORDER BY created_at_ms LIMIT $2"
    ).bind(tenant_id).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Update a decision's status and JSONB payload by its content hash.
pub async fn update_decision(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
    status: &str,
    payload: &JsonValue,
) -> Result<(), DecisionUpdateError> {
    let result = sqlx::query(
        "UPDATE decisions SET status = $1, payload = $2 WHERE id_hash = $3 AND tenant_id = $4",
    )
    .bind(status)
    .bind(payload)
    .bind(id_hash)
    .bind(tenant_id)
    .execute(pool)
    .await
    .map_err(|source| DecisionUpdateError::Query { source })?;
    if result.rows_affected() == 0 {
        return Err(DecisionUpdateError::MissingDecision {
            tenant_id: tenant_id.to_owned(),
            id_hash: id_hash.to_owned(),
        });
    }
    Ok(())
}

/// Load conflict declaration payloads for a declarant, oldest first.
pub async fn list_conflict_declaration_payloads_db(
    pool: &PgPool,
    declarant_did: &str,
) -> Result<Vec<JsonValue>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT payload FROM conflict_declarations
         WHERE declarant_did = $1
         ORDER BY timestamp_physical_ms, timestamp_logical, id_hash
         LIMIT $2",
    )
    .bind(declarant_did)
    .bind(MAX_DB_LIST_ROWS)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| row.try_get::<JsonValue, _>("payload"))
        .collect()
}

/// Row representation of a governance decision from the `decisions` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DecisionRow {
    pub id_hash: String,
    pub tenant_id: String,
    pub status: String,
    pub title: String,
    pub decision_class: String,
    pub author: String,
    pub created_at_ms: i64,
    pub constitution_version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Delegations (JSONB payload)
// ---------------------------------------------------------------------------

/// Insert a delegation record, ignoring conflicts on duplicate `id_hash`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_delegation(
    pool: &PgPool,
    id_hash: &str,
    tenant_id: &str,
    delegator: &str,
    delegatee: &str,
    created_at_ms: i64,
    expires_at: i64,
    constitution_version: &str,
    payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO delegations (id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, constitution_version, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id_hash) DO NOTHING"
    )
    .bind(id_hash).bind(tenant_id).bind(delegator).bind(delegatee)
    .bind(created_at_ms).bind(expires_at).bind(constitution_version).bind(payload)
    .execute(pool).await?;
    Ok(())
}

/// List all delegations ordered by creation timestamp.
pub async fn list_delegations_db(pool: &PgPool) -> Result<Vec<DelegationRow>, sqlx::Error> {
    sqlx::query_as::<_, DelegationRow>(
        "SELECT id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, revoked_at, constitution_version, payload FROM delegations ORDER BY created_at_ms LIMIT $1"
    ).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Check whether the given DID has an active (non-revoked) delegation as delegatee.
pub async fn has_active_delegation(pool: &PgPool, delegatee: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query(
            "SELECT 1 FROM delegations WHERE delegatee = $1 AND revoked_at IS NULL LIMIT 1",
        )
        .bind(delegatee)
        .fetch_optional(pool)
        .await?
        .is_some(),
    )
}

/// Check whether the given DID has an active delegation as either delegator or delegatee.
pub async fn has_active_delegation_either(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM delegations WHERE (delegatee = $1 OR delegator = $1) AND revoked_at IS NULL LIMIT 1")
        .bind(did).fetch_optional(pool).await?.is_some())
}

/// Row representation of a delegation record from the `delegations` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegationRow {
    pub id_hash: String,
    pub tenant_id: String,
    pub delegator: String,
    pub delegatee: String,
    pub created_at_ms: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub constitution_version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Audit entries
// ---------------------------------------------------------------------------

/// Insert an audit log entry, ignoring conflicts on duplicate sequence number.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_entry(
    pool: &PgPool,
    sequence: i64,
    prev_hash: &str,
    event_hash: &str,
    event_type: &str,
    actor: &str,
    tenant_id: &str,
    decision_id: &str,
    timestamp_physical_ms: i64,
    timestamp_logical: i32,
    entry_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(sequence).bind(prev_hash).bind(event_hash).bind(event_type)
    .bind(actor).bind(tenant_id).bind(decision_id).bind(timestamp_physical_ms)
    .bind(timestamp_logical).bind(entry_hash)
    .execute(pool).await?;
    Ok(())
}

/// List all audit entries ordered by sequence number.
pub async fn list_audit_entries(pool: &PgPool) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence LIMIT $1"
    ).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// List audit entries for one decision ordered by sequence number.
pub async fn list_audit_entries_for_decision(
    pool: &PgPool,
    decision_id: &str,
    tenant_id: &str,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash
         FROM audit_entries WHERE decision_id = $1 AND tenant_id = $2 ORDER BY sequence LIMIT $3",
    )
    .bind(decision_id)
    .bind(tenant_id)
    .bind(MAX_DB_LIST_ROWS)
    .fetch_all(pool)
    .await
}

/// Return the most recent audit entry by sequence number, or `None` if empty.
pub async fn get_last_audit_entry(pool: &PgPool) -> Result<Option<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, decision_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
    ).fetch_optional(pool).await
}

/// Return the total number of audit entries.
pub async fn count_audit_entries(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) as cnt FROM audit_entries")
        .fetch_one(pool)
        .await?
        .get::<i64, _>("cnt"))
}

/// Check whether the given actor DID appears in any audit entry.
pub async fn check_actor_in_audit(pool: &PgPool, actor: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 FROM audit_entries WHERE actor = $1 LIMIT 1")
            .bind(actor)
            .fetch_optional(pool)
            .await?
            .is_some(),
    )
}

/// Check whether the given actor has cast a vote (has a `VoteCast` audit entry).
pub async fn check_actor_voted(pool: &PgPool, actor: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 FROM audit_entries WHERE actor = $1 AND event_type = 'VoteCast' LIMIT 1",
    )
    .bind(actor)
    .fetch_optional(pool)
    .await?
    .is_some())
}

/// Row representation of an audit log entry from the `audit_entries` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub sequence: i64,
    pub prev_hash: String,
    pub event_hash: String,
    pub event_type: String,
    pub actor: String,
    pub tenant_id: String,
    pub decision_id: String,
    pub timestamp_physical_ms: i64,
    pub timestamp_logical: i32,
    pub entry_hash: String,
}

// ---------------------------------------------------------------------------
// Constitution
// ---------------------------------------------------------------------------

/// Insert or update a constitutional corpus for a tenant and version.
pub async fn upsert_constitution(
    pool: &PgPool,
    tenant_id: &str,
    version: &str,
    payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO constitutions (tenant_id, version, payload) VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, version) DO UPDATE SET payload = $3",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

/// Row representation of a constitutional corpus from the `constitutions` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConstitutionRow {
    pub tenant_id: String,
    pub version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Identity scores
// ---------------------------------------------------------------------------

/// Insert or update an identity trust score for a DID.
pub async fn upsert_identity_score(
    pool: &PgPool,
    did: &str,
    score: i32,
    tier: &str,
    factors: &JsonValue,
    last_updated: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO identity_scores (did, score, tier, factors, last_updated) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (did) DO UPDATE SET score = $2, tier = $3, factors = $4, last_updated = $5"
    ).bind(did).bind(score).bind(tier).bind(factors).bind(last_updated)
    .execute(pool).await?;
    Ok(())
}

/// Retrieve the identity trust score for a DID, or `None` if not scored.
pub async fn get_identity_score(
    pool: &PgPool,
    did: &str,
) -> Result<Option<IdentityScoreRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityScoreRow>(
        "SELECT did, score, tier, factors, last_updated FROM identity_scores WHERE did = $1",
    )
    .bind(did)
    .fetch_optional(pool)
    .await
}

/// Row representation of an identity trust score from the `identity_scores` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityScoreRow {
    pub did: String,
    pub score: i32,
    pub tier: String,
    pub factors: JsonValue,
    pub last_updated: i64,
}

// ---------------------------------------------------------------------------
// Enrollment log
// ---------------------------------------------------------------------------

/// Record an enrollment log entry for a DID (user or agent).
pub async fn insert_enrollment(
    pool: &PgPool,
    did: &str,
    entity_type: &str,
    step: &str,
    timestamp: i64,
    verified_by: &str,
    audit_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO enrollment_log (did, entity_type, step, timestamp, verified_by, audit_hash) VALUES ($1, $2, $3, $4, $5, $6)"
    ).bind(did).bind(entity_type).bind(step).bind(timestamp).bind(verified_by).bind(audit_hash)
    .execute(pool).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LiveSafe tables
// ---------------------------------------------------------------------------

/// Insert or update a LiveSafe subscriber identity record.
#[allow(clippy::too_many_arguments)]
pub async fn insert_livesafe_identity(
    pool: &PgPool,
    did: &str,
    odentity_composite_basis_points: i32,
    pace_status: &str,
    card_status: &str,
    created_at_ms: i64,
    exochain_anchor: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO livesafe_identities (did, odentity_composite_basis_points, pace_status, card_status, created_at_ms, exochain_anchor)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (did) DO UPDATE SET odentity_composite_basis_points = $2, pace_status = $3, card_status = $4, exochain_anchor = $6"
    ).bind(did).bind(odentity_composite_basis_points).bind(pace_status).bind(card_status)
    .bind(created_at_ms).bind(exochain_anchor)
    .execute(pool).await?;
    Ok(())
}

/// Retrieve a LiveSafe subscriber identity by DID, or `None` if not found.
pub async fn get_livesafe_identity(
    pool: &PgPool,
    did: &str,
) -> Result<Option<LiveSafeIdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, LiveSafeIdentityRow>(
        "SELECT did, odentity_composite_basis_points, pace_status, card_status, created_at_ms, exochain_anchor FROM livesafe_identities WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

/// Row representation of a LiveSafe identity from the `livesafe_identities` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LiveSafeIdentityRow {
    pub did: String,
    pub odentity_composite_basis_points: i32,
    pub pace_status: String,
    pub card_status: String,
    pub created_at_ms: i64,
    pub exochain_anchor: Option<String>,
}

/// Insert a LiveSafe scan receipt record.
#[allow(clippy::too_many_arguments)]
pub async fn insert_scan_receipt(
    pool: &PgPool,
    scan_id: &str,
    subscriber_did: &str,
    responder_did: &str,
    location: Option<&str>,
    scanned_at_ms: i64,
    consent_expires_at_ms: i64,
    audit_receipt_hash: &str,
    anchor_receipt: Option<&str>,
) -> Result<(), ScanReceiptInsertError> {
    if location.is_some()
        && !scan_receipt_location_consent_exists(pool, subscriber_did, responder_did, scanned_at_ms)
            .await
            .map_err(|source| ScanReceiptInsertError::Query { source })?
    {
        return Err(ScanReceiptInsertError::LocationConsentRequired);
    }

    sqlx::query(
        "INSERT INTO scan_receipts (scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    ).bind(scan_id).bind(subscriber_did).bind(responder_did).bind(location)
    .bind(scanned_at_ms).bind(consent_expires_at_ms).bind(audit_receipt_hash).bind(anchor_receipt)
    .execute(pool).await
    .map_err(|source| ScanReceiptInsertError::Query { source })?;
    Ok(())
}

async fn scan_receipt_location_consent_exists(
    pool: &PgPool,
    subscriber_did: &str,
    responder_did: &str,
    scanned_at_ms: i64,
) -> Result<bool, sqlx::Error> {
    let location_scope = serde_json::json!([LOCATION_CONSENT_SCOPE]);
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
            SELECT 1
            FROM consent_anchors
            WHERE subscriber_did = $1
              AND provider_did = $2
              AND granted_at_ms <= $3
              AND (expires_at_ms IS NULL OR expires_at_ms > $3)
              AND revoked_at_ms IS NULL
              AND scope @> $4::jsonb
        )",
    )
    .bind(subscriber_did)
    .bind(responder_did)
    .bind(scanned_at_ms)
    .bind(location_scope)
    .fetch_one(pool)
    .await
}

/// List scan receipts for a subscriber, most recent first.
pub async fn list_scan_receipts(
    pool: &PgPool,
    subscriber_did: &str,
) -> Result<Vec<ScanReceiptRow>, sqlx::Error> {
    sqlx::query_as::<_, ScanReceiptRow>(
        "SELECT scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt FROM scan_receipts WHERE subscriber_did = $1 ORDER BY scanned_at_ms DESC LIMIT $2"
    ).bind(subscriber_did).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Row representation of a scan receipt from the `scan_receipts` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScanReceiptRow {
    pub scan_id: String,
    pub subscriber_did: String,
    pub responder_did: String,
    pub location: Option<String>,
    pub scanned_at_ms: i64,
    pub consent_expires_at_ms: i64,
    pub audit_receipt_hash: String,
    pub anchor_receipt: Option<String>,
}

/// Insert a consent anchor record for a subscriber-provider pair.
#[allow(clippy::too_many_arguments)]
pub async fn insert_consent_anchor(
    pool: &PgPool,
    consent_id: &str,
    subscriber_did: &str,
    provider_did: &str,
    scope: &JsonValue,
    granted_at_ms: i64,
    expires_at_ms: Option<i64>,
    audit_receipt_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO consent_anchors (consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, audit_receipt_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    ).bind(consent_id).bind(subscriber_did).bind(provider_did).bind(scope)
    .bind(granted_at_ms).bind(expires_at_ms).bind(audit_receipt_hash)
    .execute(pool).await?;
    Ok(())
}

/// List consent anchors for a subscriber, most recent first.
pub async fn list_consent_anchors(
    pool: &PgPool,
    subscriber_did: &str,
) -> Result<Vec<ConsentAnchorRow>, sqlx::Error> {
    sqlx::query_as::<_, ConsentAnchorRow>(
        "SELECT consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, revoked_at_ms, audit_receipt_hash FROM consent_anchors WHERE subscriber_did = $1 ORDER BY granted_at_ms DESC LIMIT $2"
    ).bind(subscriber_did).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Row representation of a consent anchor from the `consent_anchors` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentAnchorRow {
    pub consent_id: String,
    pub subscriber_did: String,
    pub provider_did: String,
    pub scope: JsonValue,
    pub granted_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub audit_receipt_hash: String,
}

/// Insert a PACE trustee shard status record.
pub async fn insert_trustee_shard(
    pool: &PgPool,
    subscriber_did: &str,
    trustee_did: &str,
    role: &str,
    shard_confirmed: bool,
    accepted_at_ms: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO trustee_shard_status (subscriber_did, trustee_did, role, shard_confirmed, accepted_at_ms) VALUES ($1, $2, $3, $4, $5)"
    ).bind(subscriber_did).bind(trustee_did).bind(role).bind(shard_confirmed).bind(accepted_at_ms)
    .execute(pool).await?;
    Ok(())
}

/// List trustee shard records for a subscriber.
pub async fn list_trustee_shards(
    pool: &PgPool,
    subscriber_did: &str,
) -> Result<Vec<TrusteeShardRow>, sqlx::Error> {
    sqlx::query_as::<_, TrusteeShardRow>(
        "SELECT subscriber_did, trustee_did, role, shard_confirmed, accepted_at_ms FROM trustee_shard_status WHERE subscriber_did = $1 LIMIT $2"
    ).bind(subscriber_did).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
}

/// Row representation of a trustee shard from the `trustee_shard_status` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrusteeShardRow {
    pub subscriber_did: String,
    pub trustee_did: String,
    pub role: String,
    pub shard_confirmed: bool,
    pub accepted_at_ms: Option<i64>,
}

// ---------------------------------------------------------------------------
// Adjudication resolver tables (APE-53)
// ---------------------------------------------------------------------------

/// Row from `agent_roles` — roles held by an agent DID at a point in time.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRoleRow {
    pub agent_did: String,
    pub role: String,
    /// Constitutional branch: "executive" | "legislative" | "judicial"
    pub branch: String,
    pub granted_by: String,
    pub valid_from: i64,
    pub expires_at: Option<i64>,
}

/// Row from `consent_records` — active consent granted to an actor DID.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentRecordRow {
    pub subject_did: String,
    pub actor_did: String,
    pub scope: String,
    pub bailment_type: String,
    /// "active" | "revoked" | "expired"
    pub status: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Row from `authority_chains` — JSONB-encoded `AuthorityChain` for an actor.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityChainRow {
    pub actor_did: String,
    pub chain_json: JsonValue,
    pub valid_from: i64,
    pub expires_at: Option<i64>,
}

/// Load all non-expired roles for `actor_did` as of `now_ms`.
pub async fn load_agent_roles(
    pool: &PgPool,
    actor_did: &str,
    now_ms: i64,
) -> Result<Vec<AgentRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentRoleRow>(
        "SELECT agent_did, role, branch, granted_by, valid_from, expires_at \
         FROM agent_roles \
         WHERE agent_did = $1 \
           AND valid_from <= $2 \
           AND (expires_at IS NULL OR expires_at > $2) \
         LIMIT $3",
    )
    .bind(actor_did)
    .bind(now_ms)
    .bind(MAX_DB_LIST_ROWS)
    .fetch_all(pool)
    .await
}

/// Load all active, non-expired consent records for `actor_did` as of `now_ms`.
pub async fn load_consent_records(
    pool: &PgPool,
    actor_did: &str,
    now_ms: i64,
) -> Result<Vec<ConsentRecordRow>, sqlx::Error> {
    sqlx::query_as::<_, ConsentRecordRow>(
        "SELECT subject_did, actor_did, scope, bailment_type, status, created_at, expires_at \
         FROM consent_records \
         WHERE actor_did = $1 \
           AND status = 'active' \
           AND created_at <= $2 \
           AND (expires_at IS NULL OR expires_at > $2) \
         ORDER BY created_at DESC, subject_did ASC, scope ASC, bailment_type ASC, expires_at ASC NULLS LAST \
         LIMIT $3",
    )
    .bind(actor_did)
    .bind(now_ms)
    .bind(MAX_DB_LIST_ROWS)
    .fetch_all(pool)
    .await
}

/// Load the most-recent valid `AuthorityChain` for `actor_did` as of `now_ms`.
pub async fn load_authority_chain(
    pool: &PgPool,
    actor_did: &str,
    now_ms: i64,
) -> Result<Option<AuthorityChainRow>, sqlx::Error> {
    sqlx::query_as::<_, AuthorityChainRow>(
        "SELECT actor_did, chain_json, valid_from, expires_at \
         FROM authority_chains \
         WHERE actor_did = $1 \
           AND valid_from <= $2 \
           AND (expires_at IS NULL OR expires_at > $2) \
         ORDER BY valid_from DESC \
         LIMIT 1",
    )
    .bind(actor_did)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

// ---------------------------------------------------------------------------
// Layout templates (dashboard persistence)
// ---------------------------------------------------------------------------

/// Row representation of a layout template from the `layout_templates` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LayoutTemplateRow {
    pub id: String,
    pub user_did: Option<String>,
    pub name: String,
    pub layout_json: JsonValue,
    pub hidden_panels: JsonValue,
    pub is_built_in: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Upsert a layout template (insert or update on conflict).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_layout_template(
    pool: &PgPool,
    id: &str,
    user_did: Option<&str>,
    name: &str,
    layout_json: &JsonValue,
    hidden_panels: &JsonValue,
    is_built_in: bool,
    created_at: i64,
    updated_at: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO layout_templates (id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO UPDATE SET name = $3, layout_json = $4, hidden_panels = $5, updated_at = $8
         WHERE layout_templates.user_did = $2 AND layout_templates.is_built_in = false"
    )
    .bind(id).bind(user_did).bind(name).bind(layout_json).bind(hidden_panels)
    .bind(is_built_in).bind(created_at).bind(updated_at)
    .execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// List all layout templates for a user (or all templates if `user_did` is None).
pub async fn list_layout_templates(
    pool: &PgPool,
    user_did: Option<&str>,
) -> Result<Vec<LayoutTemplateRow>, sqlx::Error> {
    if let Some(uid) = user_did {
        sqlx::query_as::<_, LayoutTemplateRow>(
            "SELECT id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at \
             FROM layout_templates WHERE user_did = $1 OR is_built_in = true ORDER BY created_at LIMIT $2"
        ).bind(uid).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
    } else {
        sqlx::query_as::<_, LayoutTemplateRow>(
            "SELECT id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at \
             FROM layout_templates ORDER BY created_at LIMIT $1"
        ).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
    }
}

/// Delete an actor-owned layout template by ID (refuses built-in templates).
pub async fn delete_layout_template(
    pool: &PgPool,
    id: &str,
    user_did: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM layout_templates \
         WHERE id = $1 AND user_did = $2 AND is_built_in = false",
    )
    .bind(id)
    .bind(user_did)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Feedback issues (mandated reporter)
// ---------------------------------------------------------------------------

/// Row representation of a feedback issue from the `feedback_issues` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FeedbackIssueRow {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub status: String,
    pub source_widget_id: String,
    pub source_module_type: String,
    pub reporter_did: Option<String>,
    pub assigned_agent_team: Option<String>,
    pub widget_state: Option<JsonValue>,
    pub browser_info: Option<JsonValue>,
    pub resolution_notes: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Insert a new feedback issue.
#[allow(clippy::too_many_arguments)]
pub async fn insert_feedback_issue(
    pool: &PgPool,
    id: &str,
    title: &str,
    description: &str,
    severity: &str,
    category: &str,
    source_widget_id: &str,
    source_module_type: &str,
    reporter_did: Option<&str>,
    widget_state: Option<&JsonValue>,
    browser_info: Option<&JsonValue>,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO feedback_issues (id, title, description, severity, category, status, source_widget_id, source_module_type, reporter_did, widget_state, browser_info, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8, $9, $10, $11, $11)"
    )
    .bind(id).bind(title).bind(description).bind(severity).bind(category)
    .bind(source_widget_id).bind(source_module_type).bind(reporter_did)
    .bind(widget_state).bind(browser_info).bind(created_at)
    .execute(pool).await?;
    Ok(())
}

/// List feedback issues, optionally filtered by status.
pub async fn list_feedback_issues(
    pool: &PgPool,
    reporter_did: Option<&str>,
    status_filter: Option<&str>,
) -> Result<Vec<FeedbackIssueRow>, sqlx::Error> {
    match (reporter_did, status_filter) {
        (Some(reporter), Some(status)) => {
            sqlx::query_as::<_, FeedbackIssueRow>(
                "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
                 reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
                 FROM feedback_issues WHERE reporter_did = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3"
            ).bind(reporter).bind(status).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
        }
        (Some(reporter), None) => {
            sqlx::query_as::<_, FeedbackIssueRow>(
                "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
                 reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
                 FROM feedback_issues WHERE reporter_did = $1 ORDER BY created_at DESC LIMIT $2"
            ).bind(reporter).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
        }
        (None, Some(status)) => {
            sqlx::query_as::<_, FeedbackIssueRow>(
                "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
                 reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
                 FROM feedback_issues WHERE status = $1 ORDER BY created_at DESC LIMIT $2"
            ).bind(status).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
        }
        (None, None) => {
            sqlx::query_as::<_, FeedbackIssueRow>(
                "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
                 reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
                 FROM feedback_issues ORDER BY created_at DESC LIMIT $1"
            ).bind(MAX_DB_LIST_ROWS).fetch_all(pool).await
        }
    }
}

/// Update a feedback issue's status and optionally assign an agent team.
pub async fn update_feedback_issue_status(
    pool: &PgPool,
    id: &str,
    reporter_did: &str,
    status: &str,
    assigned_agent_team: Option<&str>,
    resolution_notes: Option<&str>,
    updated_at: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE feedback_issues SET status = $1, assigned_agent_team = COALESCE($2, assigned_agent_team), \
         resolution_notes = COALESCE($3, resolution_notes), updated_at = $4 WHERE id = $5 AND reporter_did = $6"
    )
    .bind(status).bind(assigned_agent_team).bind(resolution_notes)
    .bind(updated_at).bind(id).bind(reporter_did)
    .execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp};
    use sha2::{Digest, Sha384};

    use super::*;

    fn production_source() -> &'static str {
        let source = include_str!("db.rs");
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    fn migration_sources() -> String {
        [
            include_str!("../migrations/20260316000001_initial_schema.sql"),
            include_str!("../migrations/20260330000001_create_sessions.sql"),
            include_str!("../migrations/20260330000002_create_adjudication_tables.sql"),
            include_str!("../migrations/20260407000001_create_dashboard_tables.sql"),
            include_str!("../migrations/20260425000001_add_decision_id_to_audit_entries.sql"),
            include_str!("../migrations/20260426000001_livesafe_composite_basis_points.sql"),
            include_str!("../migrations/20260427000001_create_conflict_declarations.sql"),
            include_str!("../migrations/20260504000001_add_gateway_runtime_query_indexes.sql"),
            include_str!("../migrations/20260504000002_add_gateway_tenant_scope_indexes.sql"),
            include_str!("../migrations/20260504000003_create_did_documents.sql"),
            include_str!("../migrations/20260504000004_add_gateway_identity_erasure.sql"),
            include_str!(
                "../migrations/20260505000001_add_audit_decision_tenant_sequence_index.sql"
            ),
            include_str!("../migrations/20260510000001_scope_decision_ids_by_tenant.sql"),
        ]
        .join("\n")
    }

    fn migration_sources_from_disk() -> String {
        let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut entries = std::fs::read_dir(&migration_dir)
            .expect("read migrations directory")
            .map(|entry| entry.expect("migration dir entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        entries
            .into_iter()
            .map(|path| std::fs::read_to_string(path).expect("read migration"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sha384_hex(bytes: &[u8]) -> String {
        hex::encode(Sha384::digest(bytes))
    }

    fn applied_gateway_migrations() -> Vec<(&'static str, &'static [u8], &'static str)> {
        vec![
            (
                "20260316000001_initial_schema.sql",
                include_bytes!("../migrations/20260316000001_initial_schema.sql").as_slice(),
                "aa89c91d97af590b343f6dba4c411977787cf604ed4df6b55433544b49ed539fa76d863855bacc1b558be6b9d158735c",
            ),
            (
                "20260330000001_create_sessions.sql",
                include_bytes!("../migrations/20260330000001_create_sessions.sql").as_slice(),
                "8bcdb4bc2b7bfa8e66f11376a43fdd58e98902704b15556f95c016ef470192883899c2b021d472a93b8c876ed7931e42",
            ),
            (
                "20260330000002_create_adjudication_tables.sql",
                include_bytes!("../migrations/20260330000002_create_adjudication_tables.sql")
                    .as_slice(),
                concat!(
                    "c6c6e47",
                    "f",
                    "645dff8385eb2edd2a0e46971f6e1dc43bdd794286aca14c84204f7e81beeba6d5fbdf9877f28302e8b8d204"
                ),
            ),
            (
                "20260407000001_create_dashboard_tables.sql",
                include_bytes!("../migrations/20260407000001_create_dashboard_tables.sql")
                    .as_slice(),
                "536da0680b74c939f723349dc1b416ac9971686bf077aa5d5904e8924aa1541417022d28f880c4b6bfe97d3685089982",
            ),
            (
                "20260425000001_add_decision_id_to_audit_entries.sql",
                include_bytes!("../migrations/20260425000001_add_decision_id_to_audit_entries.sql")
                    .as_slice(),
                "0e8cb231c2b2405e69e65846ea87d256b1c80d82c1321647b513c10120d4cb4fc669a904cdc6df4ce1e14ba70de1bff5",
            ),
            (
                "20260426000001_livesafe_composite_basis_points.sql",
                include_bytes!("../migrations/20260426000001_livesafe_composite_basis_points.sql")
                    .as_slice(),
                concat!(
                    "5eecfe53e39663cca94c878325dbaf882e3a0a83ba0e38c7bb17fac20607f504ef6a729d797a48dcb29a93",
                    "f",
                    "329dc6e88"
                ),
            ),
            (
                "20260427000001_create_conflict_declarations.sql",
                include_bytes!("../migrations/20260427000001_create_conflict_declarations.sql")
                    .as_slice(),
                "153baeb665786a7c9d90f44d6abc4e57853c0d0d3ab334e32f6d53b9c4aa434b365264ca55e32bff7bdc3b6ec269accc",
            ),
            (
                "20260504000001_add_gateway_runtime_query_indexes.sql",
                include_bytes!(
                    "../migrations/20260504000001_add_gateway_runtime_query_indexes.sql"
                )
                .as_slice(),
                "9532a395fdf690a03e3a3f7688e31ce5848f473eec9713c7c7af4d5fe2b2561212036e4b3da2cb36fa8787764a299e41",
            ),
            (
                "20260504000002_add_gateway_tenant_scope_indexes.sql",
                include_bytes!("../migrations/20260504000002_add_gateway_tenant_scope_indexes.sql")
                    .as_slice(),
                "265edf4a9eebd0eba8870aeeeebe4ca4906d8f97a12164254080ada6c40c01fe507f42946c398bf17d51ceeefc26adce",
            ),
            (
                "20260504000003_create_did_documents.sql",
                include_bytes!("../migrations/20260504000003_create_did_documents.sql").as_slice(),
                concat!(
                    "0c08b06a5a23d474b9b3f18dc7dda2357350a2553e1ec4883dcdbbe17cf89da57a28a9d5831ba71d04de576f0",
                    "f",
                    "64fbf1"
                ),
            ),
            (
                "20260504000004_add_gateway_identity_erasure.sql",
                include_bytes!("../migrations/20260504000004_add_gateway_identity_erasure.sql")
                    .as_slice(),
                "5aaa9c662a7919a66ea93200cb6ac85e36f4486153336e63d4bab5d14e91b2a8b66f352b317815ec7658e0ecf2f28385",
            ),
            (
                "20260505000001_add_audit_decision_tenant_sequence_index.sql",
                include_bytes!(
                    "../migrations/20260505000001_add_audit_decision_tenant_sequence_index.sql"
                )
                .as_slice(),
                "584d148c3df76bad4433760f433cf4de6e5414e5825979a1aff21cd15329389343711ea43833cc1a8ab73694dc96e9aa",
            ),
            (
                "20260510000001_scope_decision_ids_by_tenant.sql",
                include_bytes!("../migrations/20260510000001_scope_decision_ids_by_tenant.sql")
                    .as_slice(),
                "8de5b45554e6c821e34b575aac7479ff5b147b86254e8bee58596118b71c679f2e65db909193ce033613dc74e5efd024",
            ),
        ]
    }

    #[test]
    fn applied_gateway_migration_checksums_are_immutable() {
        for (name, bytes, expected_checksum) in applied_gateway_migrations() {
            assert_eq!(
                sha384_hex(bytes),
                *expected_checksum,
                "applied migration {name} must remain byte-for-byte stable; add a new migration instead of editing history"
            );
        }
    }

    #[test]
    fn applied_gateway_migrations_match_disk_set() {
        let mut source_names = applied_gateway_migrations()
            .iter()
            .map(|(name, ..)| (*name).to_string())
            .collect::<Vec<_>>();
        source_names.sort();

        let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut disk_names = std::fs::read_dir(&migration_dir)
            .expect("read migrations directory")
            .map(|entry| {
                entry
                    .expect("migration dir entry")
                    .file_name()
                    .into_string()
                    .expect("migration name should be valid UTF-8")
            })
            .filter(|name| name.ends_with(".sql"))
            .collect::<Vec<_>>();
        disk_names.sort();

        assert_eq!(
            source_names, disk_names,
            "migration checksum list must mirror disk migration set exactly"
        );
    }

    fn compact_sql(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn function_source<'a>(source: &'a str, name: &str) -> &'a str {
        let signature = format!("pub async fn {name}");
        let start = source
            .find(&signature)
            .unwrap_or_else(|| panic!("{name} source must be present"));
        let after_start = &source[start..];
        let end = after_start.find("\n/// ").unwrap_or(after_start.len());
        &after_start[..end]
    }

    fn contains_in_order(source: &str, first: &str, second: &str) -> bool {
        let Some(first_index) = source.find(first) else {
            return false;
        };
        let Some(second_index) = source.find(second) else {
            return false;
        };
        first_index < second_index
    }

    async fn gateway_test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("./migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    async fn cleanup_identity_erasure_fixture(pool: &PgPool, did: &str) -> Result<(), sqlx::Error> {
        for statement in [
            "DELETE FROM did_documents WHERE did = $1",
            "DELETE FROM sessions WHERE actor_did = $1",
            "DELETE FROM users WHERE did = $1",
            "DELETE FROM agents WHERE did = $1 OR owner_did = $1",
            "DELETE FROM identity_scores WHERE did = $1",
            "DELETE FROM enrollment_log WHERE did = $1",
            "DELETE FROM livesafe_identities WHERE did = $1",
            "DELETE FROM scan_receipts WHERE subscriber_did = $1 OR responder_did = $1",
            "DELETE FROM consent_anchors WHERE subscriber_did = $1 OR provider_did = $1",
            "DELETE FROM trustee_shard_status WHERE subscriber_did = $1 OR trustee_did = $1",
            "DELETE FROM agent_roles WHERE agent_did = $1 OR granted_by = $1",
            "DELETE FROM consent_records WHERE subject_did = $1 OR actor_did = $1",
            "DELETE FROM authority_chains WHERE actor_did = $1",
            "DELETE FROM delegations WHERE delegator = $1 OR delegatee = $1",
            "DELETE FROM layout_templates WHERE user_did = $1",
            "DELETE FROM feedback_issues WHERE reporter_did = $1",
            "DELETE FROM conflict_declarations WHERE declarant_did = $1 OR related_dids @> jsonb_build_array($1::text)",
        ] {
            sqlx::query(statement).bind(did).execute(pool).await?;
        }
        Ok(())
    }

    async fn count_rows_by_did(
        pool: &PgPool,
        statement: &str,
        did: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(statement)
            .bind(did)
            .fetch_one(pool)
            .await
    }

    fn minimal_doc(did_str: &str) -> DidDocument {
        DidDocument {
            id: Did::new(did_str).expect("valid DID"),
            public_keys: vec![],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
            revoked: false,
        }
    }

    #[test]
    fn init_pool_returns_result_without_panic_paths() {
        let source = production_source();
        let init_pool_source = function_source(source, "init_pool");

        assert!(
            source.contains("pub enum DbInitError"),
            "database initialization failures must use a typed error"
        );
        assert!(
            init_pool_source.contains("-> Result<PgPool, DbInitError>"),
            "init_pool must return a typed Result instead of panicking"
        );
        assert!(
            !init_pool_source.contains(".expect("),
            "init_pool must not panic on connection or migration failure"
        );
        assert!(
            !init_pool_source.contains("#[allow(clippy::expect_used)]"),
            "init_pool must not suppress panic linting"
        );
    }

    #[test]
    fn init_pool_uses_structured_tracing_not_stdout() {
        let source = production_source();
        let init_pool_source = function_source(source, "init_pool");

        assert!(
            init_pool_source.contains("tracing::info!"),
            "database initialization events must flow through structured tracing"
        );
        assert!(
            !init_pool_source.contains("println!("),
            "database initialization must not bypass structured tracing with stdout logging"
        );
        assert!(
            !init_pool_source.contains("eprintln!("),
            "database initialization must not bypass structured tracing with stderr logging"
        );
    }

    #[test]
    fn db_init_error_display_redacts_driver_sources() {
        let source = production_source();

        assert!(
            !source.contains("failed to connect to PostgreSQL: {source}"),
            "DbInitError Display must not include driver connection details"
        );
        assert!(
            !source.contains("failed to run database migrations: {source}"),
            "DbInitError Display must not include migration driver details"
        );
        assert!(
            source.contains("#[source]"),
            "DbInitError must retain underlying sources for internal diagnostics"
        );
    }

    #[test]
    fn fetch_all_database_helpers_have_explicit_row_limits() {
        let source = production_source();
        assert!(
            source.contains("pub const MAX_DB_LIST_ROWS: i64"),
            "database list limits must be centralized"
        );

        for (name, expected_limit_clauses) in [
            ("list_users_db", 1),
            ("list_agents_db", 1),
            ("list_decisions_db", 1),
            ("list_conflict_declaration_payloads_db", 1),
            ("list_delegations_db", 1),
            ("list_audit_entries", 1),
            ("list_audit_entries_for_decision", 1),
            ("list_scan_receipts", 1),
            ("list_consent_anchors", 1),
            ("list_trustee_shards", 1),
            ("load_agent_roles", 1),
            ("load_consent_records", 1),
            ("list_layout_templates", 2),
            ("list_feedback_issues", 4),
        ] {
            let body = function_source(source, name);
            assert!(
                body.matches(".fetch_all(pool)").count() >= expected_limit_clauses,
                "{name} must keep using reviewed pool fetch paths"
            );
            assert_eq!(
                body.matches("LIMIT $").count(),
                expected_limit_clauses,
                "{name} must apply an explicit SQL LIMIT to every fetch_all query"
            );
            assert_eq!(
                body.matches(".bind(MAX_DB_LIST_ROWS)").count(),
                expected_limit_clauses,
                "{name} must bind the centralized row limit for every fetch_all query"
            );
        }
    }

    #[test]
    fn load_consent_records_orders_active_rows_deterministically() {
        let body = function_source(production_source(), "load_consent_records");
        assert!(
            body.contains(
                "ORDER BY created_at DESC, subject_did ASC, scope ASC, bailment_type ASC, expires_at ASC NULLS LAST"
            ),
            "active consent rows must have a deterministic order before adapter selection"
        );
    }

    #[test]
    fn gateway_runtime_query_filters_have_migration_indexes() {
        let migrations = compact_sql(&migration_sources());

        for index_sql in [
            "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_users_tenant_created_at ON users(tenant_id, created_at);",
            "CREATE INDEX IF NOT EXISTS idx_agents_tenant_created_at ON agents(tenant_id, created_at);",
            "CREATE INDEX IF NOT EXISTS idx_agents_created_at ON agents(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_decisions_tenant_created_at_ms ON decisions(tenant_id, created_at_ms);",
            "CREATE INDEX IF NOT EXISTS idx_decisions_created_at_ms ON decisions(created_at_ms);",
            "CREATE INDEX IF NOT EXISTS idx_delegations_created_at_ms ON delegations(created_at_ms);",
            "CREATE INDEX IF NOT EXISTS idx_delegations_active_delegatee ON delegations(delegatee) WHERE revoked_at IS NULL;",
            "CREATE INDEX IF NOT EXISTS idx_delegations_active_delegator ON delegations(delegator) WHERE revoked_at IS NULL;",
            "CREATE INDEX IF NOT EXISTS idx_audit_entries_actor_event_type ON audit_entries(actor, event_type);",
            "CREATE INDEX IF NOT EXISTS idx_audit_entries_decision_tenant_sequence ON audit_entries(decision_id, tenant_id, sequence);",
        ] {
            assert!(
                migrations.contains(index_sql),
                "gateway migration set must include runtime query index: {index_sql}"
            );
        }
    }

    #[test]
    fn did_documents_have_durable_schema_and_persistence_helpers() {
        let migrations = compact_sql(&migration_sources_from_disk());
        assert!(
            migrations.contains("CREATE TABLE IF NOT EXISTS did_documents ("),
            "DB-backed gateway identity must persist DID documents instead of relying on LocalDidRegistry memory"
        );
        assert!(
            migrations.contains("did TEXT PRIMARY KEY"),
            "persisted DID documents must be keyed by DID"
        );
        assert!(
            migrations.contains("document JSONB NOT NULL"),
            "persisted DID documents must retain the canonical serialized document payload"
        );

        let source = production_source();
        let insert_source = function_source(source, "insert_did_document");
        assert!(insert_source.contains("INSERT INTO did_documents"));
        assert!(insert_source.contains("ON CONFLICT (did) DO NOTHING"));
        assert!(insert_source.contains("rows_affected()"));

        let lookup_source = function_source(source, "find_did_document");
        assert!(lookup_source.contains("FROM did_documents"));
        assert!(lookup_source.contains("serde_json::from_value"));

        let list_source = function_source(source, "list_did_document_ids");
        assert!(list_source.contains("FROM did_documents"));
        assert!(list_source.contains("LIMIT $"));
        assert!(list_source.contains(".bind(MAX_DB_LIST_ROWS)"));
    }

    #[test]
    fn did_document_persistence_errors_do_not_display_raw_dids() {
        let sensitive_did = "did:exo:persistence-sensitive-subject";
        let payload_did = "did:exo:persistence-payload-subject";
        let serde_source =
            serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON source");

        let errors = [
            DidDocumentPersistenceError::TimestampOutOfRange {
                did: sensitive_did.to_owned(),
                field: "created",
                value: 42,
            }
            .to_string(),
            DidDocumentPersistenceError::Serialize {
                did: sensitive_did.to_owned(),
                source: serde_source,
            }
            .to_string(),
            DidDocumentPersistenceError::Deserialize {
                did: sensitive_did.to_owned(),
                source: serde_json::from_str::<serde_json::Value>("{")
                    .expect_err("invalid JSON source"),
            }
            .to_string(),
            DidDocumentPersistenceError::DocumentDidMismatch {
                row_did: sensitive_did.to_owned(),
                document_did: payload_did.to_owned(),
            }
            .to_string(),
        ];

        for error in errors {
            assert!(
                !error.contains(sensitive_did) && !error.contains(payload_did),
                "persistence error display must not expose raw DID identifiers: {error}"
            );
        }
    }

    #[test]
    fn gateway_identity_erasure_has_durable_tombstone_schema_and_helper() {
        let migrations = compact_sql(&migration_sources_from_disk());
        assert!(
            migrations
                .contains("ALTER TABLE did_documents ADD COLUMN IF NOT EXISTS erased_at_ms BIGINT"),
            "gateway DID erasure must persist a tombstone timestamp so erased DIDs cannot be re-registered after process restart"
        );

        let source = production_source();
        let helper = function_source(source, "erase_gateway_identity_records");
        for table in [
            "did_documents",
            "users",
            "agents",
            "sessions",
            "identity_scores",
            "enrollment_log",
            "livesafe_identities",
            "scan_receipts",
            "consent_anchors",
            "trustee_shard_status",
            "agent_roles",
            "consent_records",
            "authority_chains",
            "delegations",
            "layout_templates",
            "feedback_issues",
            "conflict_declarations",
        ] {
            assert!(
                helper.contains(table),
                "gateway identity erasure helper must cover durable DID-linked table {table}"
            );
        }
        assert!(
            helper.contains("revoked = true") && helper.contains("erased_at_ms"),
            "DID document erasure must tombstone the DID instead of deleting the reuse guard"
        );
    }

    #[test]
    fn scan_receipt_location_writes_require_active_location_consent() {
        let source = production_source();
        let insert = function_source(source, "insert_scan_receipt");

        assert!(
            source.contains("pub enum ScanReceiptInsertError"),
            "scan receipt writes must distinguish consent denial from SQL failure"
        );
        assert!(
            source.contains("const LOCATION_CONSENT_SCOPE: &str = \"location\";"),
            "location consent scope must be explicit and centrally named"
        );
        assert!(
            insert.contains("location.is_some()"),
            "scan receipts without location may be stored, but location-bearing receipts need consent"
        );
        assert!(
            insert.contains("scan_receipt_location_consent_exists"),
            "location-bearing scan receipts must check active consent before insert"
        );
        assert!(
            contains_in_order(
                insert,
                "scan_receipt_location_consent_exists",
                "INSERT INTO scan_receipts"
            ),
            "location consent must be checked before writing the scan_receipts row"
        );
        assert!(
            insert.contains("ScanReceiptInsertError::LocationConsentRequired"),
            "missing active location consent must fail closed with a typed error"
        );
    }

    #[tokio::test]
    async fn insert_scan_receipt_rejects_location_without_active_location_consent()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = gateway_test_pool().await else {
            return Ok(());
        };
        let subscriber = "did:exo:scan-location-subscriber-denied";
        let responder = "did:exo:scan-location-responder-denied";
        cleanup_identity_erasure_fixture(&pool, subscriber).await?;
        cleanup_identity_erasure_fixture(&pool, responder).await?;

        let err = insert_scan_receipt(
            &pool,
            "scan-location-denied",
            subscriber,
            responder,
            Some("40.7128,-74.0060"),
            1_000,
            2_000,
            "audit-location-denied",
            None,
        )
        .await
        .expect_err("location-bearing scan receipt must require active location consent");

        assert!(
            err.to_string().contains("active location consent"),
            "missing location consent should produce a typed consent error: {err}"
        );
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_receipts WHERE scan_id = $1")
                .bind("scan-location-denied")
                .fetch_one(&pool)
                .await?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn insert_scan_receipt_accepts_location_with_active_location_consent()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = gateway_test_pool().await else {
            return Ok(());
        };
        let subscriber = "did:exo:scan-location-subscriber-allowed";
        let responder = "did:exo:scan-location-responder-allowed";
        cleanup_identity_erasure_fixture(&pool, subscriber).await?;
        cleanup_identity_erasure_fixture(&pool, responder).await?;

        insert_consent_anchor(
            &pool,
            "consent-location-allowed",
            subscriber,
            responder,
            &serde_json::json!(["location"]),
            900,
            Some(2_000),
            "audit-location-consent",
        )
        .await?;
        insert_scan_receipt(
            &pool,
            "scan-location-allowed",
            subscriber,
            responder,
            Some("40.7128,-74.0060"),
            1_000,
            2_000,
            "audit-location-allowed",
            None,
        )
        .await?;

        let rows = list_scan_receipts(&pool, subscriber).await?;
        assert!(
            rows.iter().any(|row| row.scan_id == "scan-location-allowed"
                && row.location.as_deref() == Some("40.7128,-74.0060")),
            "location should persist only when active location consent exists"
        );
        Ok(())
    }

    #[tokio::test]
    async fn erase_gateway_identity_records_tombstones_did_and_removes_durable_identity_rows()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = gateway_test_pool().await else {
            return Ok(());
        };
        let did = "did:exo:erasure-db-subject";
        cleanup_identity_erasure_fixture(&pool, did).await?;

        let doc = minimal_doc(did);
        insert_did_document(&pool, &doc).await?;
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind("erasure-db-session")
        .bind(did)
        .bind(1_000_i64)
        .bind(2_000_i64)
        .execute(&pool)
        .await?;
        insert_user(
            &pool,
            did,
            "Erasure Subject",
            "erasure-db-subject@example.invalid",
            &serde_json::json!(["subject"]),
            "tenant-erasure",
            1_000,
            "Active",
            "Complete",
            "hash-to-delete",
            "salt-to-delete",
            false,
        )
        .await?;
        insert_agent(
            &pool,
            did,
            "Erasure Agent",
            "agent",
            did,
            "tenant-erasure",
            &serde_json::json!(["read"]),
            "Trusted",
            7_500,
            None,
            "Complete",
            1_000,
            "Active",
            "Routine",
        )
        .await?;
        upsert_identity_score(
            &pool,
            did,
            7_500,
            "Trusted",
            &serde_json::json!({"registered": true}),
            1_000,
        )
        .await?;
        insert_enrollment(&pool, did, "user", "pace", 1_000, did, "audit").await?;
        insert_livesafe_identity(
            &pool,
            did,
            7_500,
            "Complete",
            "Issued",
            1_000,
            Some("anchor"),
        )
        .await?;
        insert_consent_anchor(
            &pool,
            "erasure-db-location-consent",
            did,
            "did:exo:responder",
            &serde_json::json!([LOCATION_CONSENT_SCOPE]),
            999,
            Some(2_000),
            "location-consent-audit",
        )
        .await?;
        insert_scan_receipt(
            &pool,
            "erasure-db-scan",
            did,
            "did:exo:responder",
            Some("40.0,-70.0"),
            1_000,
            2_000,
            "scan-audit",
            Some("scan-anchor"),
        )
        .await?;
        insert_consent_anchor(
            &pool,
            "erasure-db-consent",
            did,
            "did:exo:provider",
            &serde_json::json!(["location"]),
            1_000,
            Some(2_000),
            "consent-audit",
        )
        .await?;
        insert_trustee_shard(&pool, did, "did:exo:trustee", "guardian", true, Some(1_000)).await?;
        sqlx::query(
            "INSERT INTO agent_roles (agent_did, role, branch, granted_by, valid_from, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)",
        )
        .bind(did)
        .bind("operator")
        .bind("executive")
        .bind(did)
        .bind(1_000_i64)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO consent_records (subject_did, actor_did, scope, bailment_type, status, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(did)
        .bind("did:exo:actor")
        .bind("read")
        .bind("standard")
        .bind("active")
        .bind(1_000_i64)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO authority_chains (actor_did, chain_json, valid_from, expires_at) \
             VALUES ($1, $2, $3, NULL)",
        )
        .bind(did)
        .bind(serde_json::json!({"chain": []}))
        .bind(1_000_i64)
        .execute(&pool)
        .await?;
        insert_delegation(
            &pool,
            "erasure-db-delegation",
            "tenant-erasure",
            did,
            "did:exo:delegatee",
            1_000,
            2_000,
            "exochain-constitution-v1",
            &serde_json::json!({"delegator": did}),
        )
        .await?;
        upsert_layout_template(
            &pool,
            "erasure-db-layout",
            Some(did),
            "Subject layout",
            &serde_json::json!([{"id": "panel", "x": 0, "y": 0}]),
            &serde_json::json!(["hidden"]),
            false,
            1_000,
            1_000,
        )
        .await?;
        insert_feedback_issue(
            &pool,
            "erasure-db-feedback",
            "Subject feedback",
            "remove reporter DID",
            "medium",
            "privacy",
            "identity-panel",
            "dashboard",
            Some(did),
            Some(&serde_json::json!({"did": did})),
            Some(&serde_json::json!({"userAgent": "test"})),
            1_000,
        )
        .await?;
        sqlx::query(
            "INSERT INTO conflict_declarations (id_hash, declarant_did, nature, related_dids, timestamp_physical_ms, timestamp_logical, payload) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind("erasure-db-conflict")
        .bind(did)
        .bind("test conflict")
        .bind(serde_json::json!(["did:exo:related"]))
        .bind(1_000_i64)
        .bind(0_i32)
        .bind(serde_json::json!({"declarant_did": did}))
        .execute(&pool)
        .await?;

        let summary = erase_gateway_identity_records(&pool, did, 9_000).await?;

        assert_eq!(summary.did_documents_tombstoned, 1);
        assert_eq!(summary.sessions_deleted, 1);
        assert_eq!(summary.users_deleted, 1);
        assert_eq!(summary.agents_deleted, 1);
        assert_eq!(summary.identity_scores_deleted, 1);
        assert_eq!(summary.enrollment_log_deleted, 1);
        assert_eq!(summary.livesafe_identities_deleted, 1);
        assert_eq!(summary.scan_receipts_deleted, 1);
        assert_eq!(summary.consent_anchors_deleted, 2);
        assert_eq!(summary.trustee_shards_deleted, 1);
        assert_eq!(summary.agent_roles_deleted, 1);
        assert_eq!(summary.consent_records_deleted, 1);
        assert_eq!(summary.authority_chains_deleted, 1);
        assert_eq!(summary.delegations_deleted, 1);
        assert_eq!(summary.layout_templates_deleted, 1);
        assert_eq!(summary.feedback_issues_deleted, 1);
        assert_eq!(summary.conflict_declarations_deleted, 1);

        assert!(find_did_document(&pool, did).await?.is_none());
        let tombstone =
            sqlx::query("SELECT revoked, erased_at_ms, document FROM did_documents WHERE did = $1")
                .bind(did)
                .fetch_one(&pool)
                .await?;
        assert!(tombstone.get::<bool, _>("revoked"));
        assert_eq!(tombstone.get::<Option<i64>, _>("erased_at_ms"), Some(9_000));
        assert_eq!(
            tombstone.get::<JsonValue, _>("document")["schema"],
            "exo.gateway.did_document_tombstone.v1"
        );
        assert!(
            !insert_did_document(&pool, &doc).await?,
            "erased DID tombstone must block DID document re-registration"
        );

        for statement in [
            "SELECT COUNT(*) FROM sessions WHERE actor_did = $1",
            "SELECT COUNT(*) FROM users WHERE did = $1",
            "SELECT COUNT(*) FROM agents WHERE did = $1 OR owner_did = $1",
            "SELECT COUNT(*) FROM identity_scores WHERE did = $1",
            "SELECT COUNT(*) FROM enrollment_log WHERE did = $1",
            "SELECT COUNT(*) FROM livesafe_identities WHERE did = $1",
            "SELECT COUNT(*) FROM scan_receipts WHERE subscriber_did = $1 OR responder_did = $1",
            "SELECT COUNT(*) FROM consent_anchors WHERE subscriber_did = $1 OR provider_did = $1",
            "SELECT COUNT(*) FROM trustee_shard_status WHERE subscriber_did = $1 OR trustee_did = $1",
            "SELECT COUNT(*) FROM agent_roles WHERE agent_did = $1 OR granted_by = $1",
            "SELECT COUNT(*) FROM consent_records WHERE subject_did = $1 OR actor_did = $1",
            "SELECT COUNT(*) FROM authority_chains WHERE actor_did = $1",
            "SELECT COUNT(*) FROM delegations WHERE delegator = $1 OR delegatee = $1",
            "SELECT COUNT(*) FROM layout_templates WHERE user_did = $1",
            "SELECT COUNT(*) FROM feedback_issues WHERE reporter_did = $1",
            "SELECT COUNT(*) FROM conflict_declarations WHERE declarant_did = $1 OR related_dids @> jsonb_build_array($1::text)",
        ] {
            assert_eq!(count_rows_by_did(&pool, statement, did).await?, 0);
        }

        cleanup_identity_erasure_fixture(&pool, did).await?;
        Ok(())
    }

    #[test]
    fn user_and_decision_list_queries_require_tenant_scope() {
        let source = production_source();
        let users = function_source(source, "list_users_db");
        let agent_lookup = function_source(source, "find_agent_by_did");
        let agents = function_source(source, "list_agents_db");
        let decisions = function_source(source, "list_decisions_db");

        assert!(
            users.contains("tenant_id: &str"),
            "list_users_db must require an explicit tenant scope"
        );
        assert!(
            compact_sql(users)
                .contains("FROM users WHERE tenant_id = $1 ORDER BY created_at LIMIT $2"),
            "list_users_db must filter by tenant_id before ordering or limiting rows"
        );
        assert!(
            contains_in_order(users, ".bind(tenant_id)", ".bind(MAX_DB_LIST_ROWS)"),
            "list_users_db must bind tenant_id before the row limit"
        );

        assert!(
            agents.contains("tenant_id: &str"),
            "list_agents_db must require an explicit tenant scope"
        );
        assert!(
            compact_sql(agents)
                .contains("FROM agents WHERE tenant_id = $1 ORDER BY created_at LIMIT $2"),
            "list_agents_db must filter by tenant_id before ordering or limiting rows"
        );
        assert!(
            contains_in_order(agents, ".bind(tenant_id)", ".bind(MAX_DB_LIST_ROWS)"),
            "list_agents_db must bind tenant_id before the row limit"
        );
        assert!(
            !compact_sql(agents).contains("FROM agents ORDER BY created_at LIMIT $1"),
            "list_agents_db must not retain an unscoped global listing query"
        );

        assert!(
            agent_lookup.contains("tenant_id: &str"),
            "find_agent_by_did must require an explicit tenant scope"
        );
        assert!(
            compact_sql(agent_lookup).contains("FROM agents WHERE did = $1 AND tenant_id = $2"),
            "find_agent_by_did must constrain agent lookup by DID and tenant_id"
        );
        assert!(
            contains_in_order(agent_lookup, ".bind(did)", ".bind(tenant_id)"),
            "find_agent_by_did must bind DID and tenant_id together"
        );

        assert!(
            decisions.contains("tenant_id: &str"),
            "list_decisions_db must require an explicit tenant scope"
        );
        assert!(
            compact_sql(decisions)
                .contains("FROM decisions WHERE tenant_id = $1 ORDER BY created_at_ms LIMIT $2"),
            "list_decisions_db must filter by tenant_id before ordering or limiting rows"
        );
        assert!(
            contains_in_order(decisions, ".bind(tenant_id)", ".bind(MAX_DB_LIST_ROWS)"),
            "list_decisions_db must bind tenant_id before the row limit"
        );
    }

    #[test]
    fn decision_lookup_requires_tenant_scope() {
        let source = production_source();
        let lookup = function_source(source, "find_decision");

        assert!(
            lookup.contains("tenant_id: &str"),
            "find_decision must require an explicit tenant scope"
        );
        assert!(
            compact_sql(lookup).contains("FROM decisions WHERE id_hash = $1 AND tenant_id = $2"),
            "find_decision must include tenant_id in the decision lookup predicate"
        );
        assert!(
            contains_in_order(lookup, ".bind(id_hash)", ".bind(tenant_id)"),
            "find_decision must bind id_hash and tenant_id together"
        );
    }

    #[test]
    fn decision_table_primary_key_is_tenant_scoped() {
        let migrations = compact_sql(&migration_sources_from_disk());
        assert!(
            migrations.contains("ALTER TABLE decisions DROP CONSTRAINT IF EXISTS decisions_pkey"),
            "tenant-scoping the historical decisions primary key must happen through a forward migration"
        );
        assert!(
            migrations
                .contains("ALTER TABLE decisions ADD CONSTRAINT decisions_pkey PRIMARY KEY (tenant_id, id_hash)"),
            "decisions must be migrated to a tenant_id + id_hash primary key so identical hashes in different tenants cannot collide"
        );
    }

    #[test]
    fn decision_write_helpers_require_tenant_scope() {
        let source = production_source();
        let insert = function_source(source, "insert_decision");
        let create = function_source(source, "create_decision");
        let update = function_source(source, "update_decision");

        assert!(
            compact_sql(insert).contains("ON CONFLICT (tenant_id, id_hash) DO UPDATE"),
            "insert_decision upserts must conflict only inside the same tenant"
        );
        assert!(
            !compact_sql(insert).contains("ON CONFLICT (id_hash) DO UPDATE"),
            "insert_decision must not upsert through a global id_hash conflict target"
        );
        assert!(
            compact_sql(create).contains("ON CONFLICT (tenant_id, id_hash) DO NOTHING"),
            "create_decision duplicate detection must be tenant-scoped"
        );
        assert!(
            update.contains("tenant_id: &str"),
            "update_decision must require an explicit tenant scope"
        );
        assert!(
            compact_sql(update).contains(
                "UPDATE decisions SET status = $1, payload = $2 WHERE id_hash = $3 AND tenant_id = $4"
            ),
            "update_decision must constrain mutations by id_hash and tenant_id"
        );
        assert!(
            contains_in_order(update, ".bind(id_hash)", ".bind(tenant_id)"),
            "update_decision must bind id_hash and tenant_id together"
        );
    }

    #[test]
    fn quorum_eligibility_counts_are_tenant_scoped_and_human_bounded() {
        let source = production_source();
        let count = function_source(source, "count_quorum_eligible_voters");

        assert!(
            count.contains("tenant_id: &str"),
            "quorum eligibility counting must require an explicit tenant scope"
        );
        assert!(
            compact_sql(count).contains("FROM users WHERE tenant_id = $1 AND status = 'Active'"),
            "human quorum eligibility must count only active users inside the authenticated tenant"
        );
        assert!(
            compact_sql(count).contains("FROM agents WHERE tenant_id = $1 AND status = 'Active'"),
            "agent quorum eligibility must count only active agents inside the authenticated tenant"
        );
        assert!(
            count.contains("delegation_id IS NOT NULL"),
            "AI agents must not be quorum-eligible without a delegated authority boundary"
        );
        assert!(
            count.contains("max_decision_class"),
            "AI quorum eligibility must be bounded by the agent's maximum decision class"
        );
        assert!(
            count.contains("eligible_human_voters: active_human_users"),
            "human quorum eligibility must not include agents or unrelated DIDs"
        );
    }

    #[tokio::test]
    async fn decision_writes_allow_same_hash_across_tenants_without_overwrite()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = gateway_test_pool().await else {
            return Ok(());
        };
        let id_hash = "tenant-scoped-decision-write";
        for tenant_id in ["tenant-a-write", "tenant-b-write"] {
            sqlx::query("DELETE FROM decisions WHERE id_hash = $1 AND tenant_id = $2")
                .bind(id_hash)
                .bind(tenant_id)
                .execute(&pool)
                .await?;
        }

        create_decision(
            &pool,
            id_hash,
            "tenant-a-write",
            "Open",
            "Tenant A",
            "Routine",
            "did:exo:tenant-a-author",
            10_000,
            "exochain-constitution-v1",
            &serde_json::json!({"tenant": "a", "status": "Open"}),
        )
        .await?;
        create_decision(
            &pool,
            id_hash,
            "tenant-b-write",
            "Open",
            "Tenant B",
            "Routine",
            "did:exo:tenant-b-author",
            10_001,
            "exochain-constitution-v1",
            &serde_json::json!({"tenant": "b", "status": "Open"}),
        )
        .await?;

        update_decision(
            &pool,
            id_hash,
            "tenant-b-write",
            "Closed",
            &serde_json::json!({"tenant": "b", "status": "Closed"}),
        )
        .await?;

        let tenant_a = find_decision(&pool, id_hash, "tenant-a-write")
            .await?
            .expect("tenant-a decision must remain present");
        let tenant_b = find_decision(&pool, id_hash, "tenant-b-write")
            .await?
            .expect("tenant-b decision must remain present");
        assert_eq!(tenant_a.status, "Open");
        assert_eq!(tenant_a.payload["tenant"], "a");
        assert_eq!(tenant_b.status, "Closed");
        assert_eq!(tenant_b.payload["tenant"], "b");

        for tenant_id in ["tenant-a-write", "tenant-b-write"] {
            sqlx::query("DELETE FROM decisions WHERE id_hash = $1 AND tenant_id = $2")
                .bind(id_hash)
                .bind(tenant_id)
                .execute(&pool)
                .await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn quorum_eligibility_counts_ignore_other_tenants_and_ineligible_agents()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = gateway_test_pool().await else {
            return Ok(());
        };
        let tenant_a = "tenant-quorum-a";
        let tenant_b = "tenant-quorum-b";
        let user_dids = [
            "did:exo:quorum-a-human-1",
            "did:exo:quorum-a-human-2",
            "did:exo:quorum-a-human-3",
            "did:exo:quorum-a-inactive-human",
            "did:exo:quorum-b-human-1",
        ];
        let agent_dids = [
            "did:exo:quorum-a-agent-routine",
            "did:exo:quorum-a-agent-operational",
            "did:exo:quorum-a-agent-strategic",
            "did:exo:quorum-a-agent-undelegated",
            "did:exo:quorum-a-agent-inactive",
            "did:exo:quorum-b-agent-constitutional",
        ];
        for did in user_dids {
            sqlx::query("DELETE FROM users WHERE did = $1")
                .bind(did)
                .execute(&pool)
                .await?;
        }
        for did in agent_dids {
            sqlx::query("DELETE FROM agents WHERE did = $1")
                .bind(did)
                .execute(&pool)
                .await?;
        }

        for (idx, did) in user_dids.iter().take(3).enumerate() {
            insert_user(
                &pool,
                did,
                "Quorum Human",
                &format!("quorum-human-{idx}@example.invalid"),
                &serde_json::json!(["member"]),
                tenant_a,
                i64::try_from(idx + 1)?,
                "Active",
                "Verified",
                "hash",
                "salt",
                true,
            )
            .await?;
        }
        insert_user(
            &pool,
            "did:exo:quorum-a-inactive-human",
            "Inactive Human",
            "quorum-inactive@example.invalid",
            &serde_json::json!(["member"]),
            tenant_a,
            10,
            "Suspended",
            "Verified",
            "hash",
            "salt",
            true,
        )
        .await?;
        insert_user(
            &pool,
            "did:exo:quorum-b-human-1",
            "Other Tenant Human",
            "quorum-other@example.invalid",
            &serde_json::json!(["member"]),
            tenant_b,
            11,
            "Active",
            "Verified",
            "hash",
            "salt",
            true,
        )
        .await?;

        for (did, delegation_id, status, max_class) in [
            (
                "did:exo:quorum-a-agent-routine",
                Some("delegation-routine"),
                "Active",
                "Routine",
            ),
            (
                "did:exo:quorum-a-agent-operational",
                Some("delegation-operational"),
                "Active",
                "Operational",
            ),
            (
                "did:exo:quorum-a-agent-strategic",
                Some("delegation-strategic"),
                "Active",
                "Strategic",
            ),
            (
                "did:exo:quorum-a-agent-undelegated",
                None,
                "Active",
                "Constitutional",
            ),
            (
                "did:exo:quorum-a-agent-inactive",
                Some("delegation-inactive"),
                "Suspended",
                "Constitutional",
            ),
        ] {
            insert_agent(
                &pool,
                did,
                "Quorum Agent",
                "delegate",
                "did:exo:quorum-a-human-1",
                tenant_a,
                &serde_json::json!(["vote"]),
                "Trusted",
                100,
                delegation_id,
                "Verified",
                20,
                status,
                max_class,
            )
            .await?;
        }
        insert_agent(
            &pool,
            "did:exo:quorum-b-agent-constitutional",
            "Other Tenant Agent",
            "delegate",
            "did:exo:quorum-b-human-1",
            tenant_b,
            &serde_json::json!(["vote"]),
            "Trusted",
            100,
            Some("delegation-other"),
            "Verified",
            21,
            "Active",
            "Constitutional",
        )
        .await?;

        let routine = count_quorum_eligible_voters(&pool, tenant_a, DecisionClass::Routine).await?;
        assert_eq!(routine.eligible_human_voters, 3);
        assert_eq!(routine.eligible_voters, 6);

        let operational =
            count_quorum_eligible_voters(&pool, tenant_a, DecisionClass::Operational).await?;
        assert_eq!(operational.eligible_human_voters, 3);
        assert_eq!(operational.eligible_voters, 5);

        let strategic =
            count_quorum_eligible_voters(&pool, tenant_a, DecisionClass::Strategic).await?;
        assert_eq!(strategic.eligible_human_voters, 3);
        assert_eq!(strategic.eligible_voters, 4);

        for did in user_dids {
            sqlx::query("DELETE FROM users WHERE did = $1")
                .bind(did)
                .execute(&pool)
                .await?;
        }
        for did in agent_dids {
            sqlx::query("DELETE FROM agents WHERE did = $1")
                .bind(did)
                .execute(&pool)
                .await?;
        }

        Ok(())
    }

    #[test]
    fn audit_entry_lookup_requires_decision_and_tenant_scope() {
        let source = production_source();
        let lookup = function_source(source, "list_audit_entries_for_decision");

        assert!(
            lookup.contains("tenant_id: &str"),
            "list_audit_entries_for_decision must require an explicit tenant scope"
        );
        assert!(
            compact_sql(lookup).contains(
                "FROM audit_entries WHERE decision_id = $1 AND tenant_id = $2 ORDER BY sequence LIMIT $3"
            ),
            "list_audit_entries_for_decision must constrain audit rows by decision_id and tenant_id"
        );
        assert!(
            contains_in_order(lookup, ".bind(decision_id)", ".bind(tenant_id)")
                && contains_in_order(lookup, ".bind(tenant_id)", ".bind(MAX_DB_LIST_ROWS)"),
            "list_audit_entries_for_decision must bind decision_id, tenant_id, then row limit"
        );
    }

    #[test]
    fn create_decision_inserts_once_without_upsert_overwrite() {
        let source = production_source();
        let create = function_source(source, "create_decision");

        assert!(
            source.contains("pub enum DecisionCreateError"),
            "create_decision must return typed duplicate-decision errors"
        );
        assert!(
            create.contains("-> Result<(), DecisionCreateError>"),
            "create_decision must distinguish duplicate ids from SQL failures"
        );
        assert!(
            compact_sql(create).contains("ON CONFLICT (tenant_id, id_hash) DO NOTHING"),
            "decision creation must not overwrite an existing decision row and duplicate detection must be tenant-scoped"
        );
        assert!(
            create.contains("rows_affected()"),
            "decision creation must inspect PgQueryResult row count"
        );
        assert!(
            create.contains("DecisionCreateError::AlreadyExists"),
            "decision creation must report a conflict when the id already exists"
        );
        assert!(
            !create.contains("DO UPDATE"),
            "decision creation must not silently mutate a pre-existing decision"
        );
    }

    #[test]
    fn update_decision_reports_missing_rows() {
        let source = production_source();
        let update = function_source(source, "update_decision");

        assert!(
            source.contains("pub enum DecisionUpdateError"),
            "update_decision must use a typed error for missing-row decisions"
        );
        assert!(
            update.contains("-> Result<(), DecisionUpdateError>"),
            "update_decision must distinguish SQL failures from missing decision rows"
        );
        assert!(
            update.contains("tenant_id: &str"),
            "update_decision must require tenant_id before mutating a decision"
        );
        assert!(
            compact_sql(update).contains(
                "UPDATE decisions SET status = $1, payload = $2 WHERE id_hash = $3 AND tenant_id = $4"
            ),
            "update_decision must update only the authenticated tenant's decision row"
        );
        assert!(
            update.contains("rows_affected()"),
            "update_decision must inspect PgQueryResult row count"
        );
        assert!(
            update.contains("DecisionUpdateError::MissingDecision"),
            "update_decision must return a missing-row error when no decision is updated"
        );
        assert!(
            !update.contains(".execute(pool).await?;\n    Ok(())"),
            "update_decision must not discard PgQueryResult and report success"
        );
    }

    #[test]
    fn pace_update_helpers_report_missing_rows() {
        let source = production_source();

        for name in ["update_user_pace", "update_agent_pace"] {
            let update = function_source(source, name);
            assert!(
                update.contains("rows_affected()"),
                "{name} must inspect PgQueryResult row count"
            );
            assert!(
                update.contains("sqlx::Error::RowNotFound"),
                "{name} must report a missing subject row instead of returning success"
            );
            assert!(
                !update.contains(".execute(pool)\n        .await?;\n    Ok(())"),
                "{name} must not discard PgQueryResult and report success"
            );
        }
    }

    #[test]
    fn pool_initialization_sets_explicit_connection_acquire_timeout() {
        let source = production_source();
        let init_pool = function_source(source, "init_pool");

        assert!(
            source.contains("const DB_POOL_ACQUIRE_TIMEOUT_SECS: u64"),
            "gateway DB pool timeout must be explicit and centrally named"
        );
        assert!(
            init_pool
                .contains(".acquire_timeout(Duration::from_secs(DB_POOL_ACQUIRE_TIMEOUT_SECS))"),
            "gateway DB pool initialization must bound waits for pooled or newly opened connections"
        );
    }

    #[test]
    fn public_user_row_has_no_password_material() {
        let row = PublicUserRow {
            did: "did:exo:user".to_owned(),
            display_name: "User".to_owned(),
            email: "user@example.invalid".to_owned(),
            roles: serde_json::json!(["member"]),
            tenant_id: "tenant".to_owned(),
            created_at: 1,
            status: "active".to_owned(),
            pace_status: "normal".to_owned(),
            mfa_enabled: true,
        };

        let debug = format!("{row:?}");
        assert!(!debug.contains("password"));
        assert!(!debug.contains("salt"));
        assert!(debug.contains("did:exo:user"));
    }

    #[test]
    fn list_users_db_never_selects_password_material() {
        let source = include_str!("db.rs");
        let Some(fn_start) = source.find("pub async fn list_users_db") else {
            panic!("list_users_db source must be present");
        };
        let after_list_users = &source[fn_start..];
        let Some(fn_end) = after_list_users.find("/// Update a user's PACE enrollment status.")
        else {
            panic!("list_users_db source terminator must be present");
        };
        let list_users_source = &after_list_users[..fn_end];

        assert!(
            !list_users_source.contains("password_hash"),
            "list_users_db must not select password hashes"
        );
        assert!(
            !list_users_source.contains("salt"),
            "list_users_db must not select password salts"
        );
        assert!(
            list_users_source.contains("Result<Vec<PublicUserRow>"),
            "list_users_db must return the public user projection"
        );
    }

    #[test]
    fn user_lookup_apis_never_select_password_material() {
        let source = include_str!("db.rs");
        for (name, terminator) in [
            ("find_user_by_email", "/// Look up a user by DID"),
            (
                "find_user_by_did",
                "/// List users for a tenant ordered by creation time.",
            ),
        ] {
            let Some(fn_start) = source.find(&format!("pub async fn {name}")) else {
                panic!("{name} source must be present");
            };
            let after_start = &source[fn_start..];
            let Some(fn_end) = after_start.find(terminator) else {
                panic!("{name} source terminator must be present");
            };
            let lookup_source = &after_start[..fn_end];

            assert!(
                !lookup_source.contains("password_hash"),
                "{name} must not select password hashes"
            );
            assert!(
                !lookup_source.contains("salt"),
                "{name} must not select password salts"
            );
            assert!(
                lookup_source.contains("Result<Option<PublicUserRow>"),
                "{name} must return the non-secret public user projection"
            );
        }
    }
}
