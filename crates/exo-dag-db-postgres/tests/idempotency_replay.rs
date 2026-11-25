#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::process;

use exo_core::{Hash256, Timestamp};
use exo_dag_db_postgres::{
    hash::RequestHashMaterial,
    idempotency::{IdempotencyDecision, IdempotencyRecordRequest, store_idempotency_response},
    postgres::DAGDB_SCHEMA_SQL,
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};

#[tokio::test]
async fn same_key_same_request_replays_cached_success() {
    let Some(db) = TestDb::maybe_new("idempotency_success").await else {
        return;
    };
    let request = record(
        "idem-success",
        request_hash(b"same"),
        201,
        json!({"memory_id": "m1"}),
    );

    let stored = store_idempotency_response(&db.pool, &request)
        .await
        .expect("store success response");
    let replayed = store_idempotency_response(&db.pool, &request)
        .await
        .expect("replay success response");

    assert!(matches!(stored, IdempotencyDecision::Stored(_)));
    let IdempotencyDecision::Replayed(cached) = replayed else {
        panic!("same request hash must replay");
    };
    assert_eq!(cached.status_code, 201);
    assert!(!cached.cached_failure);
}

#[tokio::test]
async fn same_key_different_request_returns_conflict() {
    let Some(db) = TestDb::maybe_new("idempotency_conflict").await else {
        return;
    };
    let first = record(
        "idem-conflict",
        request_hash(b"first"),
        201,
        json!({"ok": true}),
    );
    let second = record(
        "idem-conflict",
        request_hash(b"second"),
        201,
        json!({"ok": true}),
    );

    store_idempotency_response(&db.pool, &first)
        .await
        .expect("store first response");
    let conflict = store_idempotency_response(&db.pool, &second)
        .await
        .expect("conflict response is deterministic");

    assert!(matches!(
        conflict,
        IdempotencyDecision::Conflict {
            error_code: "idempotency_key_conflict"
        }
    ));
}

#[tokio::test]
async fn deterministic_duplicate_409_is_cached_and_replayed() {
    let Some(db) = TestDb::maybe_new("idempotency_duplicate").await else {
        return;
    };
    let request = record(
        "idem-duplicate",
        request_hash(b"duplicate"),
        409,
        json!({
            "error_code": "duplicate_active_memory",
            "message": "duplicate active memory"
        }),
    );

    let stored = store_idempotency_response(&db.pool, &request)
        .await
        .expect("store duplicate response");
    let replayed = store_idempotency_response(&db.pool, &request)
        .await
        .expect("replay duplicate response");

    assert!(matches!(
        stored,
        IdempotencyDecision::Stored(ref cached) if cached.cached_failure
    ));
    assert!(matches!(
        replayed,
        IdempotencyDecision::Replayed(ref cached)
            if cached.status_code == 409 && cached.cached_failure
    ));
}

#[tokio::test]
async fn uncached_failures_leave_no_idempotency_row() {
    let Some(db) = TestDb::maybe_new("idempotency_uncached").await else {
        return;
    };
    let uncached = [
        record(
            "auth-failure",
            request_hash(b"auth"),
            401,
            json!({"error_code": "unauthenticated"}),
        ),
        record(
            "validation-failure",
            request_hash(b"validation"),
            422,
            json!({"error_code": "invalid_request_shape"}),
        ),
        record(
            "timeout-failure",
            request_hash(b"timeout"),
            503,
            json!({"error_code": "dagdb_unavailable"}),
        ),
        record(
            "sanitizer-reject",
            request_hash(b"metadata"),
            422,
            json!({"error_code": "metadata_rejected"}),
        ),
    ];

    for request in &uncached {
        let decision = store_idempotency_response(&db.pool, request)
            .await
            .expect("uncached failure decision");
        assert!(matches!(decision, IdempotencyDecision::NotCached { .. }));
    }

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_idempotency_keys")
        .fetch_one(&db.pool)
        .await
        .expect("count idempotency rows");
    assert_eq!(count, 0);
}

fn record(
    idempotency_key: &str,
    request_hash: Hash256,
    status_code: u16,
    response_body: serde_json::Value,
) -> IdempotencyRecordRequest {
    IdempotencyRecordRequest {
        tenant_id: "tenant-a".into(),
        namespace: "default".into(),
        route_name: "dagdb.intake".into(),
        idempotency_key: idempotency_key.into(),
        request_hash,
        response_body,
        status_code,
        created_at: Timestamp::new(10_000, 0),
        expires_at: Timestamp::new(20_000, 0),
    }
}

fn request_hash(body: &[u8]) -> Hash256 {
    RequestHashMaterial {
        route_name: "dagdb.intake".into(),
        tenant_id: "tenant-a".into(),
        namespace: "default".into(),
        canonical_redacted_request_body: body.to_vec(),
    }
    .hash()
    .expect("request hash material serializes")
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!("skipping idempotency postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut admin = PgConnection::connect(database_url.as_str())
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut admin)
        .await
        .expect("drop existing idempotency test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create idempotency test schema");

        let scoped_url = database_url_with_search_path(&database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&scoped_url)
            .await
            .expect("connect idempotency test pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB schema");
        Some(Self {
            pool,
            schema,
            database_url,
        })
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
                    .expect("connect for idempotency cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop idempotency test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}
