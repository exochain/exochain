#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::process;

use exo_dag_db_postgres::postgres::DAGDB_SCHEMA_SQL;
use serde_json::json;
use sqlx::{Connection, PgConnection};

#[tokio::test]
async fn active_duplicate_uniqueness_allows_only_non_active_replacements() {
    let Some(mut db) = TestDb::maybe_new("persistence_duplicate").await else {
        return;
    };
    db.apply_schema().await;
    insert_receipt(&mut db.conn, bytes(1), bytes(41), "memory").await;

    insert_memory(
        &mut db.conn,
        bytes(11),
        bytes(1),
        bytes(21),
        bytes(22),
        None,
    )
    .await
    .expect("first active memory insert succeeds");
    let duplicate = insert_memory(
        &mut db.conn,
        bytes(12),
        bytes(1),
        bytes(21),
        bytes(22),
        None,
    )
    .await
    .expect_err("duplicate active memory must fail");
    assert!(
        duplicate
            .to_string()
            .contains("uq_dagdb_memory_active_duplicate"),
        "unexpected duplicate error: {duplicate}"
    );

    sqlx::query(
        "UPDATE dagdb_memory_objects \
         SET status = 'revoked', revoked_at_physical_ms = 11, revoked_at_logical = 0 \
         WHERE memory_id = $1",
    )
    .bind(bytes(11))
    .execute(&mut db.conn)
    .await
    .expect("mark first memory revoked");

    insert_memory(
        &mut db.conn,
        bytes(13),
        bytes(1),
        bytes(21),
        bytes(22),
        None,
    )
    .await
    .expect("revoked memory no longer blocks replacement");
}

#[tokio::test]
async fn transaction_failure_rolls_back_domain_rows() {
    let Some(mut db) = TestDb::maybe_new("persistence_rollback").await else {
        return;
    };
    db.apply_schema().await;

    let mut tx = db.conn.begin().await.expect("begin rollback transaction");
    insert_receipt(&mut *tx, bytes(2), bytes(42), "memory").await;
    insert_memory(&mut *tx, bytes(14), bytes(2), bytes(23), bytes(24), None)
        .await
        .expect("insert memory inside transaction");
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, status_code, created_at_physical_ms, created_at_logical, expires_at_physical_ms, expires_at_logical) \
         VALUES ('tenant-a', 'default', 'dagdb.intake', 'idem-rollback', $1, $2, '{}'::jsonb, 201, 1, 0, 2, 0)",
    )
    .bind(bytes(31))
    .bind(bytes(32))
    .execute(&mut *tx)
    .await
    .expect("insert idempotency inside transaction");
    tx.rollback()
        .await
        .expect("rollback persistence transaction");

    let memory_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_memory_objects")
        .fetch_one(&mut db.conn)
        .await
        .expect("count memory rows");
    let receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_receipts")
        .fetch_one(&mut db.conn)
        .await
        .expect("count receipt rows");
    let idempotency_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_idempotency_keys")
        .fetch_one(&mut db.conn)
        .await
        .expect("count idempotency rows");

    assert_eq!(memory_count, 0);
    assert_eq!(receipt_count, 0);
    assert_eq!(idempotency_count, 0);
}

async fn insert_receipt<'e, E>(executor: E, receipt_hash: Vec<u8>, subject_id: Vec<u8>, kind: &str)
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, $4, 1, 'intake_created', 'did:example:actor', 1, 0, $5, '{}'::jsonb, 1, 0)",
    )
    .bind(receipt_hash)
    .bind(kind)
    .bind(subject_id)
    .bind(bytes(0))
    .bind(bytes(9))
    .execute(executor)
    .await
    .expect("insert fixture receipt");
}

async fn insert_memory<'e, E>(
    executor: E,
    memory_id: Vec<u8>,
    latest_receipt_hash: Vec<u8>,
    payload_hash: Vec<u8>,
    source_hash: Vec<u8>,
    superseded_by: Option<Vec<u8>>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let metadata = json!({
        "decision": "allow",
        "text": "safe",
        "redaction_codes": [],
        "original_hash": "caac13844969e521bb8bfcf8bc706ad54bcce3e3f260368eda31bdb0542d00e1",
        "truncated": false,
        "byte_len": 4
    });
    sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, owner_did, controller_did, submitted_by_did, title, summary, keywords, risk_class, risk_bp, latest_receipt_hash, created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical, superseded_by_memory_id) \
         VALUES ($1, 'tenant-a', 'default', 'source', 'public_web', 'retrieval', $2, $3, 'did:example:owner', 'did:example:controller', 'did:example:submitter', $4, $4, '[]'::jsonb, 'R0', 0, $5, 1, 0, 1, 0, $6)",
    )
    .bind(memory_id)
    .bind(payload_hash)
    .bind(source_hash)
    .bind(metadata)
    .bind(latest_receipt_hash)
    .bind(superseded_by)
    .execute(executor)
    .await?;
    Ok(())
}

fn bytes(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

struct TestDb {
    conn: PgConnection,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!("skipping persistence postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut conn = PgConnection::connect(database_url.as_str())
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut conn)
        .await
        .expect("drop existing test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut conn)
            .await
            .expect("create test schema");
        let mut db = Self {
            conn,
            schema,
            database_url,
        };
        db.set_search_path().await;
        Some(db)
    }

    async fn set_search_path(&mut self) {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "SET search_path TO {}, public",
            self.schema
        )))
        .execute(&mut self.conn)
        .await
        .expect("set DAG DB test search_path");
    }

    async fn apply_schema(&mut self) {
        self.set_search_path().await;
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply DAG DB schema");
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let schema = self.schema.clone();
        let database_url = self.database_url.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("create cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop DAG DB test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}
