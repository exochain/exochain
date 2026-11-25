#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{process, sync::Arc};

use exo_core::{Hash256, Timestamp};
use exo_dag_db_api::{ReceiptEventType, SubjectKind};
use exo_dag_db_postgres::{
    postgres::DAGDB_SCHEMA_SQL,
    receipt::{ReceiptAppendRequest, ReceiptStoreError, append_receipt, reconstruct_receipt_chain},
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use tokio::sync::Barrier;

#[tokio::test]
async fn concurrent_first_receipt_creation_replays_same_event() {
    let Some(db) = TestDb::maybe_new("receipt_same_genesis").await else {
        return;
    };
    let request = receipt_request(bytes(11), Hash256::ZERO, bytes(91));
    let barrier = Arc::new(Barrier::new(2));

    let left = spawn_append(db.pool.clone(), barrier.clone(), request.clone());
    let right = spawn_append(db.pool.clone(), barrier, request);

    let left = left
        .await
        .expect("left append task joins")
        .expect("left append");
    let right = right
        .await
        .expect("right append task joins")
        .expect("right append");

    assert_eq!(left.receipt_hash, right.receipt_hash);
    assert_eq!(
        [left.created_new, right.created_new]
            .into_iter()
            .filter(|created| *created)
            .count(),
        1
    );

    let chain = reconstruct_receipt_chain(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        bytes(11),
    )
    .await
    .expect("reconstruct first receipt chain");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].prev_receipt_hash, Hash256::ZERO);
    assert_eq!(chain[0].seq, 1);
}

#[tokio::test]
async fn concurrent_first_receipt_creation_rejects_different_event() {
    let Some(db) = TestDb::maybe_new("receipt_different_genesis").await else {
        return;
    };
    let barrier = Arc::new(Barrier::new(2));
    let left = spawn_append(
        db.pool.clone(),
        barrier.clone(),
        receipt_request(bytes(12), Hash256::ZERO, bytes(92)),
    );
    let right = spawn_append(
        db.pool.clone(),
        barrier,
        receipt_request(bytes(12), Hash256::ZERO, bytes(93)),
    );

    let outcomes = [
        left.await.expect("left append task joins"),
        right.await.expect("right append task joins"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(result) if result.created_new))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(ReceiptStoreError::StalePreviousReceiptHash)))
            .count(),
        1
    );
}

#[tokio::test]
async fn sequential_append_stale_previous_hash_and_replay_are_deterministic() {
    let Some(db) = TestDb::maybe_new("receipt_sequential").await else {
        return;
    };
    let first = append_receipt(
        &db.pool,
        &receipt_request(bytes(13), Hash256::ZERO, bytes(94)),
    )
    .await
    .expect("append first receipt");
    assert!(first.created_new);

    let replay = append_receipt(
        &db.pool,
        &receipt_request(bytes(13), Hash256::ZERO, bytes(94)),
    )
    .await
    .expect("replay first receipt");
    assert!(!replay.created_new);
    assert_eq!(replay.receipt_hash, first.receipt_hash);

    let second = append_receipt(
        &db.pool,
        &receipt_request(bytes(13), first.receipt_hash, bytes(95)),
    )
    .await
    .expect("append second receipt");
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_receipt_hash, first.receipt_hash);

    let stale = append_receipt(
        &db.pool,
        &receipt_request(bytes(13), first.receipt_hash, bytes(96)),
    )
    .await
    .expect_err("fork after stale previous hash must fail");
    assert!(matches!(stale, ReceiptStoreError::StalePreviousReceiptHash));

    let duplicate_genesis = append_receipt(
        &db.pool,
        &receipt_request(bytes(13), Hash256::ZERO, bytes(97)),
    )
    .await
    .expect_err("different duplicate genesis must fail");
    assert!(matches!(
        duplicate_genesis,
        ReceiptStoreError::StalePreviousReceiptHash
    ));

    let chain = reconstruct_receipt_chain(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        bytes(13),
    )
    .await
    .expect("reconstruct two-receipt chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].seq, 1);
    assert_eq!(chain[1].seq, 2);
    assert_eq!(chain[1].prev_receipt_hash, chain[0].receipt_hash);
}

#[tokio::test]
async fn first_receipt_with_non_genesis_previous_hash_is_rejected() {
    let Some(db) = TestDb::maybe_new("receipt_non_genesis_first").await else {
        return;
    };
    let error = append_receipt(&db.pool, &receipt_request(bytes(14), bytes(77), bytes(98)))
        .await
        .expect_err("first receipt must use Hash256::ZERO as previous hash");
    assert!(matches!(error, ReceiptStoreError::StalePreviousReceiptHash));
}

fn spawn_append(
    pool: PgPool,
    barrier: Arc<Barrier>,
    request: ReceiptAppendRequest,
) -> tokio::task::JoinHandle<
    Result<exo_dag_db_postgres::receipt::ReceiptAppendResult, ReceiptStoreError>,
> {
    tokio::spawn(async move {
        barrier.wait().await;
        append_receipt(&pool, &request).await
    })
}

fn receipt_request(
    subject_id: Hash256,
    expected_prev_receipt_hash: Hash256,
    event_body_hash: Hash256,
) -> ReceiptAppendRequest {
    ReceiptAppendRequest {
        tenant_id: "tenant-a".into(),
        namespace: "default".into(),
        subject_kind: SubjectKind::Memory,
        subject_id,
        expected_prev_receipt_hash,
        event_type: ReceiptEventType::IntakeCreated,
        actor_did: "did:example:agent".into(),
        event_hlc: Timestamp::new(10_000, event_body_hash.as_bytes()[0].into()),
        event_body_hash,
        receipt_body: json!({
            "event": "intake_created",
            "safe": true
        }),
    }
}

fn bytes(byte: u8) -> Hash256 {
    Hash256::from_bytes([byte; 32])
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!("skipping receipt postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set");
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
        .expect("drop existing receipt test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create receipt test schema");

        let scoped_url = database_url_with_search_path(&database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&scoped_url)
            .await
            .expect("connect receipt test pool");
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
                    .expect("connect for receipt cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop receipt test schema");
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
