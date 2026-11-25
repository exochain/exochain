//! Feature-gated PostgreSQL repository foundation for ExoChain DAG DB.
//!
//! This slice exposes migration and connection primitives only. Domain writes,
//! receipt CAS, idempotency replay, and outbox workers are implemented by later
//! slices on top of this foundation.

use std::time::Duration;

use sqlx::{
    AssertSqlSafe, Postgres, Transaction,
    migrate::Migrator,
    postgres::{PgPool, PgPoolOptions},
};
use thiserror::Error;

pub mod context_packet_persistence;
pub mod continuation_persistence;
pub mod default_route;
pub mod kg_catalog_router;
pub mod kg_context_selection;
pub mod kg_context_selection_write;
pub mod kg_export;
pub mod kg_import;
pub mod kg_retrieval;
pub mod kg_writeback;
pub mod lifecycle_action;
pub mod route_invalidation;

/// SQL migration source for the additive DAG DB schema.
///
/// Includes the base schema and the strictly-additive PRD-D3 (D3-S1) nullable
/// `deep_detail_summary` column migration, so isolated test schemas that apply
/// this constant carry the two-tier column without a separate apply step.
pub const DAGDB_SCHEMA_SQL: &str = concat!(
    include_str!("../../migrations/20260505000001_create_dagdb_schema.sql"),
    "\n",
    include_str!("../../migrations/20260612000003_add_dagdb_memory_deep_detail_summary.sql"),
    "\n",
    include_str!("../../migrations/20260620000001_add_dagdb_operational_receipt_event_types.sql"),
    "\n",
    include_str!("../../migrations/20260623000001_create_root_bundle_receipt_schema.sql"),
    "\n",
    include_str!("../../migrations/20260623000002_create_dagdb_node_store_schema.sql"),
    "\n",
    include_str!("../../migrations/20260623000003_create_zerodentity_record_schema.sql"),
    "\n",
    include_str!("../../migrations/20260623000004_create_gateway_state_records_schema.sql"),
    "\n",
    include_str!("../../migrations/20260623000005_create_gateway_legacy_table_contracts.sql")
);

/// SQL migration source for additive graph edge tombstone tables.
pub const DAGDB_GRAPH_EDGE_TOMBSTONE_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260602000001_create_dagdb_graph_edge_tombstones.sql");

/// SQL migration source for additive layered graph tables.
pub const DAGDB_LAYERED_GRAPH_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260602000002_create_dagdb_layered_graph_schema.sql");

/// SQL migration source for additive memory graph organization tables.
pub const DAGDB_GRAPH_SCHEMA_SQL: &str = concat!(
    include_str!("../../migrations/20260505000002_create_dagdb_graph_schema.sql"),
    "\n",
    include_str!("../../migrations/20260602000001_create_dagdb_graph_edge_tombstones.sql"),
    "\n",
    include_str!("../../migrations/20260602000002_create_dagdb_layered_graph_schema.sql"),
    "\n",
    include_str!("../../migrations/20260612000002_add_dagdb_graph_layers_aggregate_summary.sql")
);

/// SQL migration source for additive KG portable export persistence tables.
pub const DAGDB_EXPORT_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260511000001_create_dagdb_export_persistence_schema.sql");

/// SQL migration source for operational receipt event types added after export persistence.
pub const DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260620000001_add_dagdb_operational_receipt_event_types.sql");

/// SQL migration source for the PR #708 operational event-type and tenant RLS expansion.
pub const DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL: &str = include_str!(
    "../../migrations/20260623000006_add_dagdb_operational_event_types_and_rls_expansion.sql"
);

/// SQL migration source for additive KG export finality/outbox subject support.
pub const DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260511000002_create_dagdb_export_finality_outbox_schema.sql");

/// SQL migration source for additive PRD17B default-route tables.
pub const DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260607000001_create_prd17_default_route_schema.sql");

/// SQL migration source for additive PRD17B context-packet tables.
pub const DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260607000002_create_prd17_context_packet_schema.sql");

/// SQL migration source for additive PRD17C lifecycle tables.
pub const DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260607000003_create_prd17_lifecycle_schema.sql");

/// SQL migration source for tenant-scoped row-level security policies.
pub const DAGDB_TENANT_RLS_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260619000001_enable_dagdb_tenant_rls.sql");

/// SQL migration source for the PRD-D4 telemetry-facet node_type extension.
///
/// Extends the `dagdb_memory_objects` `node_type` CHECK with the dedicated
/// `usage_event` value so usage-event telemetry has its own structural home.
/// Additive and idempotent; rewrites no rows.
pub const DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL: &str =
    include_str!("../../migrations/20260612000001_create_dagdb_telemetry_facet_node_type.sql");

/// Root/domain catalog rows without raw payloads hash catalog material.
pub const CATALOG_ROOT_HASH_SEMANTICS: &str =
    "root/domain catalog payload_hash and source_hash are canonical catalog material hashes";

const DB_POOL_ACQUIRE_TIMEOUT_SECS: u64 = 5;

/// Dedicated Postgres schema that owns the DAG DB tables and their migration
/// ledger.
///
/// SQLx 0.8 hardcodes the migration-tracking table name (`_sqlx_migrations`)
/// and has no per-`Migrator` table override. The gateway crate and this crate
/// reuse the same integer migration versions (`20260505000001`,
/// `20260602000001`) for entirely different SQL, so running both migrators
/// against one shared `_sqlx_migrations` table would collide on version with a
/// mismatched checksum and abort. Provisioning the DAG DB schema (tables *and*
/// its `_sqlx_migrations` ledger) inside this dedicated schema gives the DAG DB
/// migrator its own tracking, so the two migrators cannot collide. The gateway
/// runtime adds this schema to its connection `search_path` so the bare-named
/// DAG DB queries resolve here while gateway tables resolve in `public`.
pub const DAGDB_MIGRATION_SCHEMA: &str = "dagdb";

/// Errors raised by the DAG DB Postgres repository foundation.
#[derive(Debug, Error)]
pub enum DagDbPostgresError {
    /// PostgreSQL connection failed.
    #[error("failed to connect to ExoChain DAG DB PostgreSQL database")]
    Connect {
        /// Source sqlx error.
        #[source]
        source: sqlx::Error,
    },
    /// Migration execution failed.
    #[error("failed to run ExoChain DAG DB migrations")]
    Migrate {
        /// Source migration error.
        #[source]
        source: sqlx::migrate::MigrateError,
    },
    /// The requested migration schema name is not a safe SQL identifier.
    #[error("invalid DAG DB migration schema name: {schema}")]
    InvalidSchema {
        /// The rejected schema name.
        schema: String,
    },
    /// Provisioning the dedicated migration schema failed.
    #[error("failed to provision the dedicated DAG DB migration schema")]
    SchemaSetup {
        /// Source sqlx error.
        #[source]
        source: sqlx::Error,
    },
    /// Closing the migration connection after mutating session state failed.
    #[error("failed to close the dedicated DAG DB migration connection for schema {schema}")]
    MigrationConnectionClose {
        /// Migration schema whose connection could not be closed.
        schema: String,
        /// Source sqlx error.
        #[source]
        source: sqlx::Error,
    },
    /// Migration execution failed, then closing the migration connection also failed.
    #[error(
        "failed to run ExoChain DAG DB migrations and close the dedicated DAG DB migration connection for schema {schema}: close failed: {close}"
    )]
    MigrationAndConnectionClose {
        /// Migration schema whose connection could not be closed.
        schema: String,
        /// Source migration error.
        #[source]
        migration: sqlx::migrate::MigrateError,
        /// Source close error. Boxed so the error enum stays under clippy's
        /// `result_large_err` threshold (sqlx 0.9 grew `sqlx::Error`).
        close: Box<sqlx::Error>,
    },
}

/// Result alias for Postgres foundation functions.
pub type Result<T> = std::result::Result<T, DagDbPostgresError>;

/// Return the SQLx migrator for additive DAG DB migrations.
#[must_use]
pub fn migrator() -> &'static Migrator {
    static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
    &MIGRATOR
}

/// Connect to Postgres and run additive DAG DB migrations.
pub async fn init_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(DB_POOL_ACQUIRE_TIMEOUT_SECS))
        .connect(database_url)
        .await
        .map_err(|source| DagDbPostgresError::Connect { source })?;

    run_migrations(&pool).await?;
    Ok(pool)
}

/// Run additive DAG DB migrations on an existing pool.
///
/// Migrations are applied against the connection's existing `search_path`. For
/// the canonical, collision-free provisioning path used by the deployed
/// gateway, prefer [`run_migrations_in_schema`].
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    migrator()
        .run(pool)
        .await
        .map_err(|source| DagDbPostgresError::Migrate { source })
}

/// Bind a tenant id for RLS-protected DAG DB tables inside the current
/// transaction.
pub async fn bind_tenant_context(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('exo.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Begin a transaction and bind its tenant context before tenant-scoped reads.
pub async fn begin_tenant_transaction<'a>(
    pool: &'a PgPool,
    tenant_id: &str,
) -> std::result::Result<Transaction<'a, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    bind_tenant_context(&mut tx, tenant_id).await?;
    Ok(tx)
}

/// Validate that `schema` is a safe, unquoted Postgres identifier so it can be
/// interpolated into DDL that cannot be parameterized.
fn validate_schema_identifier(schema: &str) -> Result<()> {
    let valid = !schema.is_empty()
        && schema.len() <= 63
        && schema
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && schema
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(DagDbPostgresError::InvalidSchema {
            schema: schema.to_owned(),
        })
    }
}

/// Provision the DAG DB schema into a dedicated Postgres schema, applying the
/// additive DAG DB migrations through the canonical ledgered migrator.
///
/// This is the single authoritative provisioning path. The dedicated schema
/// holds the DAG DB tables *and* their `_sqlx_migrations` ledger, so the DAG DB
/// migrator tracks its own migrations independently of any other migrator
/// (notably the gateway's `public._sqlx_migrations`) on a shared database. The
/// schema is created if absent. The runner is idempotent.
///
/// Callers that read DAG DB tables with bare (unqualified) names must include
/// `schema` on their connection `search_path`.
pub async fn run_migrations_in_schema(pool: &PgPool, schema: &str) -> Result<()> {
    validate_schema_identifier(schema)?;

    // `schema` passed validate_schema_identifier above ([a-z_][a-z0-9_]{0,62});
    // DDL identifiers cannot be bound as parameters.
    sqlx::query(AssertSqlSafe(format!(
        "CREATE SCHEMA IF NOT EXISTS {schema}"
    )))
    .execute(pool)
    .await
    .map_err(|source| DagDbPostgresError::SchemaSetup { source })?;

    // Run the migrator on a single dedicated connection whose session-level
    // search_path points at the dedicated schema first. SQLx creates its bare
    // `_sqlx_migrations` table — and every bare `CREATE TABLE` in the migration
    // bodies — in the first writable schema on the search_path, so both the
    // ledger and the DAG DB tables land in `schema`. `public` is kept on the
    // path so the migrations can still reference shared extensions/types.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|source| DagDbPostgresError::SchemaSetup { source })?;
    // `schema` passed validate_schema_identifier above.
    sqlx::query(AssertSqlSafe(format!(
        "SET search_path TO {schema}, public"
    )))
    .execute(&mut *conn)
    .await
    .map_err(|source| DagDbPostgresError::SchemaSetup { source })?;

    let migration_result = migrator().run(&mut *conn).await;

    // Close (rather than recycle) this connection so its migration-scoped
    // session `search_path` is never inherited by a later pool checkout.
    let close_result = conn.close().await;

    finish_schema_migration(schema, migration_result, close_result)
}

fn finish_schema_migration(
    schema: &str,
    migration_result: std::result::Result<(), sqlx::migrate::MigrateError>,
    close_result: std::result::Result<(), sqlx::Error>,
) -> Result<()> {
    match (migration_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(DagDbPostgresError::Migrate { source }),
        (Ok(()), Err(source)) => Err(DagDbPostgresError::MigrationConnectionClose {
            schema: schema.to_owned(),
            source,
        }),
        (Err(migration), Err(close)) => Err(DagDbPostgresError::MigrationAndConnectionClose {
            schema: schema.to_owned(),
            migration,
            close: Box::new(close),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_source_contains_only_dagdb_tables() {
        let lower = DAGDB_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_receipts"));
        assert!(lower.contains("create table if not exists dagdb_inbound_agent_credentials"));
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
    }

    #[test]
    fn graph_migration_source_contains_only_dagdb_graph_tables() {
        let lower = DAGDB_GRAPH_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_graph_nodes"));
        assert!(lower.contains("create table if not exists dagdb_graph_route_invalidations"));
        assert!(lower.contains("create table if not exists dagdb_graph_edge_tombstones"));
        assert!(lower.contains("create table if not exists dagdb_graph_layers"));
        assert!(lower.contains("create table if not exists dagdb_graph_layer_memberships"));
        assert!(lower.contains("create table if not exists dagdb_graph_layer_edges"));
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
    }

    #[test]
    fn export_migration_source_contains_only_dagdb_export_tables() {
        let lower = DAGDB_EXPORT_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_exports"));
        assert!(lower.contains("create table if not exists dagdb_export_challenges"));
        assert!(lower.contains("export_created"));
        assert!(lower.contains("export_challenge_verified"));
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
        assert!(!lower.contains("dagdb_dag_outbox"));
        assert!(!lower.contains("raw_markdown"));
        assert!(!lower.contains("raw_private_payload"));
        assert!(!lower.contains("raw_model_output"));
    }

    #[test]
    fn export_finality_outbox_migration_is_narrow() {
        let lower = DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("alter table dagdb_dag_outbox"));
        assert!(lower.contains("dagdb_dag_outbox_subject_kind_check"));
        assert!(lower.contains("'export'"));
        assert!(!lower.contains("create table"));
        assert!(!lower.contains("dag_nodes"));
        assert!(!lower.contains("dag_committed"));
        assert!(!lower.contains("dagdb_graph_route_invalidations"));
        assert!(!lower.contains("raw_markdown"));
        assert!(!lower.contains("raw_private_payload"));
        assert!(!lower.contains("raw_model_output"));
        assert!(!lower.contains("source_excerpt"));
    }

    #[test]
    fn prd17_default_route_migration_is_narrow() {
        let lower = DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_default_routes"));
        assert!(lower.contains("selected_memory_refs jsonb not null"));
        assert!(lower.contains("selected_memory_ref_count integer not null"));
        assert!(
            lower
                .contains("route_source in ('persisted', 'preview', 'dry_run', 'target_artifact')")
        );
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
        assert!(!lower.contains("raw_markdown"));
        assert!(!lower.contains("raw_private_payload"));
        assert!(!lower.contains("raw_model_output"));
    }

    #[test]
    fn prd17_context_packet_migration_is_narrow() {
        let lower = DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_context_packet_records"));
        assert!(lower.contains("idempotency_key text not null"));
        assert!(
            lower.contains("unique (tenant_id, project_id, memory_namespace, idempotency_key)")
        );
        assert!(lower.contains("source_proof_refs jsonb not null"));
        assert!(lower.contains("target_artifact_only"));
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
        assert!(!lower.contains("raw_private_payload"));
        assert!(!lower.contains("raw_model_output"));
    }

    #[test]
    fn prd17_lifecycle_migration_is_narrow() {
        let lower = DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL.to_ascii_lowercase();
        assert!(lower.contains("create table if not exists dagdb_lifecycle_actions"));
        assert!(lower.contains("create table if not exists dagdb_lifecycle_rollbacks"));
        assert!(lower.contains("create table if not exists dagdb_route_invalidation_events"));
        assert!(lower.contains("create table if not exists dagdb_continuation_records"));
        assert!(lower.contains("tenant_id text not null"));
        assert!(lower.contains(
            "idx_dagdb_continuation_records_task on dagdb_continuation_records using btree (tenant_id, project_id, memory_namespace, task_id)"
        ));
        assert!(lower.contains("production_lifecycle_approval"));
        assert!(!lower.contains("create table dag_nodes"));
        assert!(!lower.contains("alter table dag_nodes"));
        assert!(!lower.contains("create table dag_committed"));
        assert!(!lower.contains("alter table dag_committed"));
        assert!(!lower.contains("raw_private_payload"));
        assert!(!lower.contains("raw_model_output"));
    }

    #[test]
    fn catalog_root_hash_semantics_are_explicit() {
        assert!(CATALOG_ROOT_HASH_SEMANTICS.contains("catalog material hashes"));
        assert!(DAGDB_SCHEMA_SQL.contains("canonical hash of catalog material"));
    }

    #[test]
    fn migrator_declares_schema_migration() {
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260505000001),
            "DAG DB schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260505000002),
            "DAG DB graph schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260511000001),
            "DAG DB export persistence schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260511000002),
            "DAG DB export finality/outbox schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260602000001),
            "DAG DB graph edge tombstone migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260602000002),
            "DAG DB layered graph schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260607000001),
            "DAG DB PRD17B default-route schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260607000002),
            "DAG DB PRD17B context-packet schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260607000003),
            "DAG DB PRD17C lifecycle schema migration must be registered"
        );
        assert!(
            migrator()
                .iter()
                .any(|migration| migration.version == 20260623000006),
            "DAG DB PR #708 operational event/RLS expansion migration must be registered"
        );
    }

    #[tokio::test]
    async fn init_pool_fails_loudly_for_invalid_database_url() {
        let error = init_pool("not-a-postgres-url")
            .await
            .expect_err("invalid URL must fail before migrations can silently skip");
        assert!(matches!(error, DagDbPostgresError::Connect { .. }));
        assert_eq!(
            error.to_string(),
            "failed to connect to ExoChain DAG DB PostgreSQL database"
        );
    }

    #[test]
    fn finish_schema_migration_preserves_migration_and_close_failures() {
        assert!(finish_schema_migration(DAGDB_MIGRATION_SCHEMA, Ok(()), Ok(())).is_ok());

        let migration_only = finish_schema_migration(
            DAGDB_MIGRATION_SCHEMA,
            Err(sqlx::migrate::MigrateError::VersionMissing(42)),
            Ok(()),
        )
        .expect_err("migration failure must be returned");
        assert!(matches!(
            migration_only,
            DagDbPostgresError::Migrate {
                source: sqlx::migrate::MigrateError::VersionMissing(42)
            }
        ));

        let close_only = finish_schema_migration(
            DAGDB_MIGRATION_SCHEMA,
            Ok(()),
            Err(sqlx::Error::RowNotFound),
        )
        .expect_err("close failure must be returned");
        assert!(matches!(
            close_only,
            DagDbPostgresError::MigrationConnectionClose {
                schema,
                source: sqlx::Error::RowNotFound,
            } if schema == DAGDB_MIGRATION_SCHEMA
        ));

        let dual_failure = finish_schema_migration(
            DAGDB_MIGRATION_SCHEMA,
            Err(sqlx::migrate::MigrateError::VersionMissing(42)),
            Err(sqlx::Error::RowNotFound),
        )
        .expect_err("dual failure must be returned");
        assert!(matches!(
            dual_failure,
            DagDbPostgresError::MigrationAndConnectionClose {
                schema,
                migration: sqlx::migrate::MigrateError::VersionMissing(42),
                close,
            } if schema == DAGDB_MIGRATION_SCHEMA
                && matches!(*close, sqlx::Error::RowNotFound)
        ));
    }
}
