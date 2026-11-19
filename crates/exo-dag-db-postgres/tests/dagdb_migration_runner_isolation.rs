#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! GAP-012 T4: the dag-db schema is provisioned by a single ledgered migration
//! runner, with its own migration-tracking table, so it cannot collide with the
//! gateway's `_sqlx_migrations` on a shared database.
//!
//! These tests reproduce the cross-crate version collision (`20260505000001`
//! and `20260602000001` are reused by both crates) and prove the dedicated-schema
//! runner provisions the dag-db tables and answers a representative query without
//! disturbing — or being disturbed by — the gateway-owned tracking table.

use std::process;

use exo_dag_db_postgres::postgres::{DAGDB_MIGRATION_SCHEMA, run_migrations_in_schema};
use sqlx::{
    Row,
    postgres::{PgPool, PgPoolOptions},
};

/// Versions reused by BOTH exo-dag-db and exo-gateway migrators. If the two
/// migrators ever share one `_sqlx_migrations` table these collide on checksum.
const CROSS_CRATE_COLLISION_VERSIONS: [i64; 2] = [20260505000001, 20260602000001];

struct TestPool {
    pool: PgPool,
    schema: String,
}

impl TestPool {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!(
                "skipping dag-db migration runner isolation test: \
                 EXO_DAGDB_TEST_DATABASE_URL is not set"
            );
            return None;
        };
        let schema = format!("dagdb_runner_{label}_{}", process::id());
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&pool)
        .await
        .expect("drop existing runner test schema");
        Some(Self { pool, schema })
    }

    async fn drop_schema(&self) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {} CASCADE",
            self.schema
        )))
        .execute(&self.pool)
        .await
        .expect("drop runner test schema");
    }
}

/// The dedicated-schema runner provisions the dag-db tables and its OWN
/// `_sqlx_migrations` ledger inside the target schema, and a representative
/// dag-db query answers against that freshly provisioned schema.
#[tokio::test]
async fn schema_scoped_runner_provisions_tables_and_own_ledger() {
    let Some(test) = TestPool::maybe_new("provision").await else {
        return;
    };

    run_migrations_in_schema(&test.pool, &test.schema)
        .await
        .expect("dag-db schema-scoped runner must provision a fresh schema");

    // Idempotent: a second run against the same schema is a no-op, not an error.
    run_migrations_in_schema(&test.pool, &test.schema)
        .await
        .expect("dag-db schema-scoped runner must be idempotent");

    // The dag-db tables live in the dedicated schema.
    let table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name LIKE 'dagdb_%'",
    )
    .bind(&test.schema)
    .fetch_one(&test.pool)
    .await
    .expect("count dag-db tables in dedicated schema");
    assert!(
        table_count >= 30,
        "expected the full dag-db table set in the dedicated schema, found {table_count}"
    );

    // The runner has its OWN `_sqlx_migrations` ledger inside the dedicated
    // schema (separate tracking), recording the dag-db migration versions.
    let ledger_versions: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT version FROM {}._sqlx_migrations ORDER BY version",
        test.schema
    )))
    .fetch_all(&test.pool)
    .await
    .expect("the dedicated schema must carry its own _sqlx_migrations ledger");
    for version in CROSS_CRATE_COLLISION_VERSIONS {
        assert!(
            ledger_versions.contains(&version),
            "dag-db ledger in {} must record version {version}",
            test.schema
        );
    }

    // A representative dag-db query answers against the provisioned schema: the
    // memory-objects table (queried by the runtime) is present and queryable.
    let memory_rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {}.dagdb_memory_objects",
        test.schema
    )))
    .fetch_one(&test.pool)
    .await
    .expect("representative dag-db query must answer against the provisioned schema");
    assert_eq!(memory_rows, 0, "fresh schema starts with no memory objects");

    test.drop_schema().await;
}

/// The dag-db runner does not collide with a gateway-owned `_sqlx_migrations`
/// that already records the shared version integers under a DIFFERENT checksum.
/// Reproduces the production failure mode on a shared database.
#[tokio::test]
async fn dagdb_runner_does_not_collide_with_gateway_migration_ledger() {
    let Some(test) = TestPool::maybe_new("collision").await else {
        return;
    };

    // Stand up a gateway-style ledger in a separate "gateway" schema that already
    // records the colliding versions with gateway checksums. (We use a sibling
    // schema rather than `public` so the shared test database is not polluted,
    // while still exercising the cross-crate version reuse.)
    let gateway_schema = format!("{}_gateway", test.schema);
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {gateway_schema}"
    )))
    .execute(&test.pool)
    .await
    .expect("create gateway-style schema");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE {gateway_schema}._sqlx_migrations ( \
            version BIGINT PRIMARY KEY, \
            description TEXT NOT NULL, \
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), \
            success BOOLEAN NOT NULL, \
            checksum BYTEA NOT NULL, \
            execution_time BIGINT NOT NULL )"
    )))
    .execute(&test.pool)
    .await
    .expect("create gateway-style _sqlx_migrations");
    for version in CROSS_CRATE_COLLISION_VERSIONS {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {gateway_schema}._sqlx_migrations \
             (version, description, success, checksum, execution_time) \
             VALUES ($1, 'gateway-owned migration', true, $2, 0)"
        )))
        .bind(version)
        // A gateway checksum that is deliberately different from the dag-db one.
        .bind(vec![0xAB_u8; 48])
        .execute(&test.pool)
        .await
        .expect("seed gateway-owned colliding version");
    }

    // The dag-db runner provisions its dedicated schema. Because it keeps its own
    // ledger, it must NOT raise a checksum/version mismatch against the
    // gateway-owned ledger.
    run_migrations_in_schema(&test.pool, &test.schema)
        .await
        .expect("dag-db runner must not collide with a gateway-owned migration ledger");

    // The gateway ledger is untouched: still exactly the two gateway rows with
    // their gateway checksums.
    let gateway_rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT version, checksum FROM {gateway_schema}._sqlx_migrations ORDER BY version"
    )))
    .fetch_all(&test.pool)
    .await
    .expect("read gateway ledger after dag-db run");
    assert_eq!(gateway_rows.len(), CROSS_CRATE_COLLISION_VERSIONS.len());
    for row in &gateway_rows {
        let checksum: Vec<u8> = row.get("checksum");
        assert_eq!(
            checksum,
            vec![0xAB_u8; 48],
            "gateway ledger checksums must be untouched by the dag-db runner"
        );
    }

    // The dag-db ledger lives in its own schema and records the same version
    // integers under the dag-db checksums — separate tracking, no collision.
    let dagdb_versions: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT version FROM {}._sqlx_migrations ORDER BY version",
        test.schema
    )))
    .fetch_all(&test.pool)
    .await
    .expect("dag-db ledger present in dedicated schema");
    for version in CROSS_CRATE_COLLISION_VERSIONS {
        assert!(
            dagdb_versions.contains(&version),
            "dag-db ledger must record version {version} independently"
        );
    }

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {gateway_schema} CASCADE"
    )))
    .execute(&test.pool)
    .await
    .expect("drop gateway-style schema");
    test.drop_schema().await;
}

/// The canonical schema constant is the dedicated `dagdb` schema name.
#[test]
fn migration_schema_constant_is_dagdb() {
    assert_eq!(DAGDB_MIGRATION_SCHEMA, "dagdb");
}
