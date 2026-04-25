//! PostgreSQL persistence layer for EXOCHAIN decision.forum.
//!
//! Replaces in-memory AppState Vecs/HashMaps with real database operations.
//! Complex governance objects (DecisionObject, Delegation) are stored as
//! JSONB payloads with indexed scalar columns for efficient queries.

use serde_json::Value as JsonValue;
use sqlx::{
    Row,
    postgres::{PgPool, PgPoolOptions},
};

// ---------------------------------------------------------------------------
// Pool initialization
// ---------------------------------------------------------------------------

/// Create a connection pool and run migrations.
#[allow(clippy::expect_used)]
pub async fn init_pool(database_url: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    println!("[DB] Connected to PostgreSQL, migrations applied");
    pool
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
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users WHERE email = $1"
    ).bind(email).fetch_optional(pool).await
}

/// Look up a user by DID, returning `None` if not found.
pub async fn find_user_by_did(pool: &PgPool, did: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

/// List all users ordered by creation time.
pub async fn list_users_db(pool: &PgPool) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users ORDER BY created_at"
    ).fetch_all(pool).await
}

/// Update a user's PACE enrollment status.
pub async fn update_user_pace(
    pool: &PgPool,
    did: &str,
    pace_status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET pace_status = $1 WHERE did = $2")
        .bind(pace_status)
        .bind(did)
        .execute(pool)
        .await?;
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

/// Row representation of a user record from the `users` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub did: String,
    pub display_name: String,
    pub email: String,
    pub roles: JsonValue,
    pub tenant_id: String,
    pub created_at: i64,
    pub status: String,
    pub pace_status: String,
    pub password_hash: String,
    pub salt: String,
    pub mfa_enabled: bool,
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
pub async fn find_agent_by_did(pool: &PgPool, did: &str) -> Result<Option<AgentRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentRow>(
        "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

/// List agents, optionally filtered by tenant ID, ordered by creation time.
pub async fn list_agents_db(
    pool: &PgPool,
    tenant_id: Option<&str>,
) -> Result<Vec<AgentRow>, sqlx::Error> {
    if let Some(tid) = tenant_id {
        sqlx::query_as::<_, AgentRow>(
            "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE tenant_id = $1 ORDER BY created_at"
        ).bind(tid).fetch_all(pool).await
    } else {
        sqlx::query_as::<_, AgentRow>(
            "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents ORDER BY created_at"
        ).fetch_all(pool).await
    }
}

/// Update an agent's PACE enrollment status.
pub async fn update_agent_pace(
    pool: &PgPool,
    did: &str,
    pace_status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET pace_status = $1 WHERE did = $2")
        .bind(pace_status)
        .bind(did)
        .execute(pool)
        .await?;
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
         ON CONFLICT (id_hash) DO UPDATE SET status = $3, payload = $9"
    )
    .bind(id_hash).bind(tenant_id).bind(status).bind(title).bind(decision_class)
    .bind(author).bind(created_at_ms).bind(constitution_version).bind(payload)
    .execute(pool).await?;
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
) -> Result<Option<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions WHERE id_hash = $1"
    ).bind(id_hash).fetch_optional(pool).await
}

/// List all decisions ordered by creation timestamp.
pub async fn list_decisions_db(pool: &PgPool) -> Result<Vec<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions ORDER BY created_at_ms"
    ).fetch_all(pool).await
}

/// Update a decision's status and JSONB payload by its content hash.
pub async fn update_decision(
    pool: &PgPool,
    id_hash: &str,
    status: &str,
    payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE decisions SET status = $1, payload = $2 WHERE id_hash = $3")
        .bind(status)
        .bind(payload)
        .bind(id_hash)
        .execute(pool)
        .await?;
    Ok(())
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
        "SELECT id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, revoked_at, constitution_version, payload FROM delegations ORDER BY created_at_ms"
    ).fetch_all(pool).await
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
    timestamp_physical_ms: i64,
    timestamp_logical: i32,
    entry_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (sequence) DO NOTHING"
    )
    .bind(sequence).bind(prev_hash).bind(event_hash).bind(event_type)
    .bind(actor).bind(tenant_id).bind(timestamp_physical_ms).bind(timestamp_logical)
    .bind(entry_hash)
    .execute(pool).await?;
    Ok(())
}

/// List all audit entries ordered by sequence number.
pub async fn list_audit_entries(pool: &PgPool) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence"
    ).fetch_all(pool).await
}

/// Return the most recent audit entry by sequence number, or `None` if empty.
pub async fn get_last_audit_entry(pool: &PgPool) -> Result<Option<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
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
    odentity_composite: f64,
    pace_status: &str,
    card_status: &str,
    created_at_ms: i64,
    exochain_anchor: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO livesafe_identities (did, odentity_composite, pace_status, card_status, created_at_ms, exochain_anchor)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (did) DO UPDATE SET odentity_composite = $2, pace_status = $3, card_status = $4, exochain_anchor = $6"
    ).bind(did).bind(odentity_composite).bind(pace_status).bind(card_status)
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
        "SELECT did, odentity_composite, pace_status, card_status, created_at_ms, exochain_anchor FROM livesafe_identities WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

/// Row representation of a LiveSafe identity from the `livesafe_identities` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LiveSafeIdentityRow {
    pub did: String,
    pub odentity_composite: f64,
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
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO scan_receipts (scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    ).bind(scan_id).bind(subscriber_did).bind(responder_did).bind(location)
    .bind(scanned_at_ms).bind(consent_expires_at_ms).bind(audit_receipt_hash).bind(anchor_receipt)
    .execute(pool).await?;
    Ok(())
}

/// List scan receipts for a subscriber, most recent first.
pub async fn list_scan_receipts(
    pool: &PgPool,
    subscriber_did: &str,
) -> Result<Vec<ScanReceiptRow>, sqlx::Error> {
    sqlx::query_as::<_, ScanReceiptRow>(
        "SELECT scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt FROM scan_receipts WHERE subscriber_did = $1 ORDER BY scanned_at_ms DESC"
    ).bind(subscriber_did).fetch_all(pool).await
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
        "SELECT consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, revoked_at_ms, audit_receipt_hash FROM consent_anchors WHERE subscriber_did = $1 ORDER BY granted_at_ms DESC"
    ).bind(subscriber_did).fetch_all(pool).await
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
        "SELECT subscriber_did, trustee_did, role, shard_confirmed, accepted_at_ms FROM trustee_shard_status WHERE subscriber_did = $1"
    ).bind(subscriber_did).fetch_all(pool).await
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
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(actor_did)
    .bind(now_ms)
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
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(actor_did)
    .bind(now_ms)
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
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO layout_templates (id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO UPDATE SET name = $3, layout_json = $4, hidden_panels = $5, updated_at = $8"
    )
    .bind(id).bind(user_did).bind(name).bind(layout_json).bind(hidden_panels)
    .bind(is_built_in).bind(created_at).bind(updated_at)
    .execute(pool).await?;
    Ok(())
}

/// List all layout templates for a user (or all templates if `user_did` is None).
pub async fn list_layout_templates(
    pool: &PgPool,
    user_did: Option<&str>,
) -> Result<Vec<LayoutTemplateRow>, sqlx::Error> {
    if let Some(uid) = user_did {
        sqlx::query_as::<_, LayoutTemplateRow>(
            "SELECT id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at \
             FROM layout_templates WHERE user_did = $1 OR is_built_in = true ORDER BY created_at"
        ).bind(uid).fetch_all(pool).await
    } else {
        sqlx::query_as::<_, LayoutTemplateRow>(
            "SELECT id, user_did, name, layout_json, hidden_panels, is_built_in, created_at, updated_at \
             FROM layout_templates ORDER BY created_at"
        ).fetch_all(pool).await
    }
}

/// Delete a layout template by ID (refuses to delete built-in templates).
pub async fn delete_layout_template(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM layout_templates WHERE id = $1 AND is_built_in = false")
        .bind(id)
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
    status_filter: Option<&str>,
) -> Result<Vec<FeedbackIssueRow>, sqlx::Error> {
    if let Some(status) = status_filter {
        sqlx::query_as::<_, FeedbackIssueRow>(
            "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
             reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
             FROM feedback_issues WHERE status = $1 ORDER BY created_at DESC"
        ).bind(status).fetch_all(pool).await
    } else {
        sqlx::query_as::<_, FeedbackIssueRow>(
            "SELECT id, title, description, severity, category, status, source_widget_id, source_module_type, \
             reporter_did, assigned_agent_team, widget_state, browser_info, resolution_notes, created_at, updated_at \
             FROM feedback_issues ORDER BY created_at DESC"
        ).fetch_all(pool).await
    }
}

/// Update a feedback issue's status and optionally assign an agent team.
pub async fn update_feedback_issue_status(
    pool: &PgPool,
    id: &str,
    status: &str,
    assigned_agent_team: Option<&str>,
    resolution_notes: Option<&str>,
    updated_at: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE feedback_issues SET status = $1, assigned_agent_team = COALESCE($2, assigned_agent_team), \
         resolution_notes = COALESCE($3, resolution_notes), updated_at = $4 WHERE id = $5"
    )
    .bind(status).bind(assigned_agent_team).bind(resolution_notes)
    .bind(updated_at).bind(id)
    .execute(pool).await?;
    Ok(result.rows_affected() > 0)
}
