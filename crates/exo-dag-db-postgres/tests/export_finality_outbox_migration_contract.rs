#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use exo_dag_db_postgres::postgres::{DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL, init_pool, migrator};
use sqlx::{PgPool, postgres::PgPoolOptions};

const EXPORT_FINALITY_OUTBOX_MIGRATION_VERSION: i64 = 20260511000002;
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
    "export_artifact",
];

#[test]
fn export_finality_outbox_migration_source_is_narrow_and_additive() {
    let lower = DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL.to_ascii_lowercase();
    assert!(lower.contains("alter table dagdb_dag_outbox"));
    assert!(lower.contains("dagdb_dag_outbox_subject_kind_check"));
    assert!(lower.contains("'export'"));
    assert!(!lower.contains("create table"));
    assert!(!lower.contains("dag_nodes"));
    assert!(!lower.contains("dag_committed"));
    assert!(!lower.contains("dagdb_graph_route_invalidations"));
    assert!(!lower.contains("insert into"));
    assert!(!lower.contains("update dagdb_dag_outbox"));
    for fragment in FORBIDDEN_COLUMN_FRAGMENTS {
        assert!(
            !lower.contains(fragment),
            "export finality/outbox migration must not contain forbidden raw/private fragment {fragment}"
        );
    }
}

#[test]
fn export_finality_outbox_migration_is_registered() {
    assert!(
        migrator()
            .iter()
            .any(|migration| migration.version == EXPORT_FINALITY_OUTBOX_MIGRATION_VERSION),
        "export finality/outbox migration must be registered"
    );
}

#[tokio::test]
async fn export_finality_outbox_migration_live_schema_contract() {
    let Some(db) = TestDb::new("export_finality_outbox_migration").await else {
        return;
    };
    let pool = init_pool(&db.scoped_url)
        .await
        .expect("init_pool must apply export finality/outbox migration");

    assert_export_outbox_constraint(&pool).await;
    assert_export_outbox_columns_do_not_store_raw_material(&pool).await;
    assert_export_subject_kind_is_accepted(&pool).await;
    assert_unsupported_subject_kind_is_rejected(&pool).await;
    assert_no_route_invalidation_rows(&pool).await;
    assert_no_exo_dag_tables(&pool).await;

    pool.close().await;
    db.cleanup().await;
}

async fn assert_export_outbox_constraint(pool: &PgPool) {
    let definitions = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_constraintdef(con.oid) AS definition \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid = con.conrelid \
         JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
         WHERE ns.nspname = current_schema() \
           AND rel.relname = 'dagdb_dag_outbox' \
           AND con.conname = 'dagdb_dag_outbox_subject_kind_check'",
    )
    .fetch_all(pool)
    .await
    .expect("query dagdb_dag_outbox subject constraint");
    assert_eq!(definitions.len(), 1);
    assert!(
        definitions[0].contains("'export'::text"),
        "dagdb_dag_outbox subject constraint must allow export"
    );
}

async fn assert_export_outbox_columns_do_not_store_raw_material(pool: &PgPool) {
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'dagdb_dag_outbox' \
         ORDER BY ordinal_position",
    )
    .fetch_all(pool)
    .await
    .expect("query dagdb_dag_outbox columns");
    assert_eq!(
        columns,
        vec![
            "outbox_id".to_owned(),
            "tenant_id".to_owned(),
            "namespace".to_owned(),
            "subject_kind".to_owned(),
            "subject_id".to_owned(),
            "dag_write_id".to_owned(),
            "dag_payload_hash".to_owned(),
            "dag_finality_status".to_owned(),
            "attempt_count".to_owned(),
            "max_attempts".to_owned(),
            "next_attempt_at_physical_ms".to_owned(),
            "next_attempt_at_logical".to_owned(),
            "last_error_code".to_owned(),
            "dag_receipt_hash".to_owned(),
            "compensation_receipt_hash".to_owned(),
            "created_at_physical_ms".to_owned(),
            "created_at_logical".to_owned(),
            "updated_at_physical_ms".to_owned(),
            "updated_at_logical".to_owned(),
        ]
    );
    for column in columns {
        let lower = column.to_ascii_lowercase();
        for fragment in FORBIDDEN_COLUMN_FRAGMENTS {
            assert!(
                !lower.contains(fragment),
                "dagdb_dag_outbox.{column} must not persist forbidden raw/private material"
            );
        }
    }
}

async fn assert_export_subject_kind_is_accepted(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO dagdb_dag_outbox \
         (outbox_id, tenant_id, namespace, subject_kind, subject_id, dag_write_id, dag_payload_hash, \
          dag_finality_status, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-test', 'dag-db', 'export', $2, 'dagdb-export-finality-test', $3, \
                 'pending', 1, 0, 1, 1)",
    )
    .bind(bytes(0x11))
    .bind(bytes(0x12))
    .bind(bytes(0x13))
    .execute(pool)
    .await
    .expect("dagdb_dag_outbox must accept export subject kind");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_dag_outbox \
         WHERE tenant_id = 'tenant-test' AND namespace = 'dag-db' AND subject_kind = 'export'",
    )
    .fetch_one(pool)
    .await
    .expect("count export outbox rows");
    assert_eq!(count, 1);
}

async fn assert_unsupported_subject_kind_is_rejected(pool: &PgPool) {
    let result = sqlx::query(
        "INSERT INTO dagdb_dag_outbox \
         (outbox_id, tenant_id, namespace, subject_kind, subject_id, dag_write_id, dag_payload_hash, \
          dag_finality_status, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-test', 'dag-db', 'raw_export_artifact', $2, 'unsupported-kind-test', $3, \
                 'pending', 1, 0, 1, 1)",
    )
    .bind(bytes(0x21))
    .bind(bytes(0x22))
    .bind(bytes(0x23))
    .execute(pool)
    .await;
    assert!(
        result.is_err(),
        "unsupported dagdb_dag_outbox subject kind must remain rejected"
    );
}

async fn assert_no_route_invalidation_rows(pool: &PgPool) {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_route_invalidations")
        .fetch_one(pool)
        .await
        .expect("count route invalidations");
    assert_eq!(count, 0);
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

fn bytes(value: u8) -> Vec<u8> {
    [value; 32].to_vec()
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
                "skipping export_finality_outbox_migration live test: EXO_DAGDB_TEST_DATABASE_URL is not set"
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
