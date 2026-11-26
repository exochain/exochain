#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use exo_dag_db_postgres::postgres::{DAGDB_EXPORT_SCHEMA_SQL, init_pool, migrator};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

const EXPORT_MIGRATION_VERSION: i64 = 20260511000001;
const FORBIDDEN_COLUMN_FRAGMENTS: &[&str] = &[
    "raw_body",
    "raw_markdown",
    "raw_private_payload",
    "raw_model_output",
    "source_excerpt",
    "gateway_secret",
    "database_url",
    "db_url",
    "private_key",
    "absolute_path",
];

#[test]
fn export_persistence_migration_source_is_narrow_and_additive() {
    let lower = DAGDB_EXPORT_SCHEMA_SQL.to_ascii_lowercase();
    assert!(lower.contains("create table if not exists dagdb_exports"));
    assert!(lower.contains("create table if not exists dagdb_export_challenges"));
    assert!(lower.contains("export_created"));
    assert!(lower.contains("export_verified"));
    assert!(lower.contains("export_failed"));
    assert!(lower.contains("export_challenge_created"));
    assert!(lower.contains("export_challenge_verified"));
    assert!(!lower.contains("dagdb_dag_outbox"));
    assert!(!lower.contains("create table dag_nodes"));
    assert!(!lower.contains("alter table dag_nodes"));
    assert!(!lower.contains("create table dag_committed"));
    assert!(!lower.contains("alter table dag_committed"));
    assert!(!lower.contains("route_invalidations"));
    for fragment in FORBIDDEN_COLUMN_FRAGMENTS {
        assert!(
            !lower.contains(fragment),
            "export migration must not contain forbidden raw/private fragment {fragment}"
        );
    }
}

#[test]
fn export_persistence_migration_is_registered() {
    assert!(
        migrator()
            .iter()
            .any(|migration| migration.version == EXPORT_MIGRATION_VERSION),
        "export persistence migration must be registered"
    );
}

#[tokio::test]
async fn export_persistence_migration_live_schema_contract() {
    let Some(db) = TestDb::new("export_persistence_migration").await else {
        return;
    };
    let pool = init_pool(&db.scoped_url)
        .await
        .expect("init_pool must apply export persistence migration");

    assert_export_tables(&pool).await;
    assert_export_columns(&pool).await;
    assert_export_constraints(&pool).await;
    assert_export_indexes(&pool).await;
    assert_no_exo_dag_tables(&pool).await;

    pool.close().await;
    db.cleanup().await;
}

async fn assert_export_tables(pool: &PgPool) {
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'dagdb_export%' \
         ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .expect("query export tables");
    assert_eq!(
        tables,
        vec![
            "dagdb_export_challenges".to_owned(),
            "dagdb_exports".to_owned(),
        ]
    );
}

async fn assert_export_columns(pool: &PgPool) {
    for (table, columns) in expected_columns() {
        let actual = sqlx::query_scalar::<_, String>(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 \
             ORDER BY ordinal_position",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap_or_else(|err| panic!("query columns for {table}: {err}"));
        assert_eq!(actual, columns, "column names for {table}");
        for column in actual {
            let lower = column.to_ascii_lowercase();
            for fragment in FORBIDDEN_COLUMN_FRAGMENTS {
                assert!(
                    !lower.contains(fragment),
                    "{table}.{column} must not persist forbidden raw/private material"
                );
            }
        }
    }
}

async fn assert_export_constraints(pool: &PgPool) {
    let constraints = sqlx::query(
        "SELECT rel.relname AS table_name, pg_get_constraintdef(con.oid) AS definition \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid = con.conrelid \
         JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
         WHERE ns.nspname = current_schema() \
           AND rel.relname IN ('dagdb_exports','dagdb_export_challenges','dagdb_receipts','dagdb_subject_receipt_heads')",
    )
    .fetch_all(pool)
    .await
    .expect("query export constraints");
    assert_constraint(
        &constraints,
        "dagdb_exports",
        "schema_version = 'dagdb_kg_portable_export_v1'::text",
    );
    assert_constraint(
        &constraints,
        "dagdb_exports",
        "octet_length(export_id) = 32",
    );
    assert_constraint(&constraints, "dagdb_exports", "export_status = ANY");
    assert_constraint(
        &constraints,
        "dagdb_export_challenges",
        "challenge_kind = ANY",
    );
    assert_constraint(
        &constraints,
        "dagdb_export_challenges",
        "proof_algorithm = 'hash_commitment_v1'::text",
    );
    assert_constraint(&constraints, "dagdb_receipts", "export");
    assert_constraint(&constraints, "dagdb_receipts", "dagdb_export_completed");
    assert_constraint(&constraints, "dagdb_receipts", "export_challenge_verified");
    assert_constraint(&constraints, "dagdb_subject_receipt_heads", "export");
}

fn assert_constraint(rows: &[sqlx::postgres::PgRow], table: &str, snippet: &str) {
    assert!(
        rows.iter().any(|row| {
            row.get::<String, _>("table_name") == table
                && row.get::<String, _>("definition").contains(snippet)
        }),
        "missing constraint snippet {snippet:?} on {table}"
    );
}

async fn assert_export_indexes(pool: &PgPool) {
    let indexes = sqlx::query_scalar::<_, String>(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = current_schema() AND indexname LIKE 'idx_dagdb_export%' \
         ORDER BY indexname",
    )
    .fetch_all(pool)
    .await
    .expect("query export indexes");
    for expected in [
        "idx_dagdb_export_challenges_export",
        "idx_dagdb_export_challenges_status",
        "idx_dagdb_exports_receipt",
        "idx_dagdb_exports_scope_hash",
        "idx_dagdb_exports_scope_status",
    ] {
        assert!(
            indexes.iter().any(|index| index == expected),
            "missing {expected}"
        );
    }
}

async fn assert_no_exo_dag_tables(pool: &PgPool) {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = current_schema() \
           AND table_name IN ('dag_nodes','dag_committed')",
    )
    .fetch_one(pool)
    .await
    .expect("count exo-dag tables");
    assert_eq!(count, 0);
}

fn expected_columns() -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "dagdb_exports",
            vec![
                "export_id",
                "tenant_id",
                "namespace",
                "schema_version",
                "export_scope_hash",
                "source_commit_or_repo_ref",
                "included_memory_ids_hash",
                "included_receipt_heads_hash",
                "section_hashes",
                "section_counts",
                "citation_index_hash",
                "provenance_index_hash",
                "redaction_summary_hash",
                "omission_summary_hash",
                "verification_hash",
                "whole_export_hash",
                "export_status",
                "authority_ref_hash",
                "consent_ref_hash",
                "approval_ref_hash",
                "requester_did",
                "latest_receipt_hash",
                "created_at_physical_ms",
                "created_at_logical",
                "updated_at_physical_ms",
                "updated_at_logical",
            ],
        ),
        (
            "dagdb_export_challenges",
            vec![
                "challenge_id",
                "tenant_id",
                "namespace",
                "export_id",
                "challenge_kind",
                "challenge_hash",
                "proof_hash",
                "proof_algorithm",
                "verifier_did",
                "verification_status",
                "verification_notes_hash",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
    ]
    .into_iter()
    .map(|(table, columns)| {
        (
            table,
            columns.into_iter().map(str::to_owned).collect::<Vec<_>>(),
        )
    })
    .collect()
}

struct TestDb {
    admin_pool: PgPool,
    scoped_url: String,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!(
                "skipping export_persistence_migration live test: EXO_DAGDB_TEST_DATABASE_URL is not set"
            );
            return None;
        };
        let schema = format!("dagdb_{label}_{}", std::process::id());
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect admin Postgres pool");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#
        )))
        .execute(&admin_pool)
        .await
        .expect("drop isolated schema");
        sqlx::query(sqlx::AssertSqlSafe(format!(r#"CREATE SCHEMA "{schema}""#)))
            .execute(&admin_pool)
            .await
            .expect("create isolated schema");
        Some(Self {
            admin_pool,
            scoped_url: database_url_with_search_path(&database_url, &schema),
            schema,
        })
    }

    async fn cleanup(self) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#,
            self.schema
        )))
        .execute(&self.admin_pool)
        .await
        .expect("drop isolated schema after test");
        self.admin_pool.close().await;
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}
