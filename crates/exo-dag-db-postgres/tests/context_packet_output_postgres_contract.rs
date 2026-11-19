#![cfg(feature = "postgres")]
#![allow(clippy::expect_used)]

use std::process;

use exo_dag_db_postgres::{
    context_packet_persistence::{
        CONTEXT_PACKET_RECORD_SCHEMA_VERSION, ContextPacketRecord, DefaultContextQuality,
        PacketFreshnessStatus, PacketPersistenceStatus, PacketValidationStatus,
        canonical_idempotency_key,
    },
    postgres::{
        DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL,
        context_packet_persistence::{ContextPacketPostgresError, persist_context_packet_record},
    },
};
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};

fn record_for_scope(
    packet_id: &str,
    tenant_id: &str,
    project_id: &str,
    memory_namespace: &str,
) -> ContextPacketRecord {
    ContextPacketRecord {
        schema_version: CONTEXT_PACKET_RECORD_SCHEMA_VERSION.to_owned(),
        packet_id: packet_id.to_owned(),
        route_id: "route-prd17b-001".to_owned(),
        query_hash: "query-hash-prd17b-001".to_owned(),
        tenant_id: tenant_id.to_owned(),
        project_id: project_id.to_owned(),
        memory_namespace: memory_namespace.to_owned(),
        selected_memory_ids: vec!["memory-prd17b-001".to_owned()],
        selected_edge_ids: Vec::new(),
        token_budget: 1_000,
        token_estimate: 200,
        context_quality: DefaultContextQuality::UsableContext,
        citation_coverage_bp: 10_000,
        validation_coverage_bp: 10_000,
        freshness_status: PacketFreshnessStatus::Current,
        validation_status: PacketValidationStatus::Passed,
        source_proof_refs: vec!["receipt-prd17b-001".to_owned()],
        fallback_reason: None,
        idempotency_key: canonical_idempotency_key(
            "route-prd17b-001",
            "query-hash-prd17b-001",
            1_000,
        ),
        persistence_status: PacketPersistenceStatus::ProofBound,
        production_default_route_approval_status: "operator_deferred".to_owned(),
        packet_quality_review_status: "operator_deferred".to_owned(),
        created_at: "2026-06-09T00:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn context_packet_record_rejects_cross_scope_and_mutated_packet_id_replays() {
    let Some(db) = TestDb::maybe_new("ctx_packet_replay_guard").await else {
        return;
    };
    let record = record_for_scope("packet-prd17b-001", "tenant-a", "project-a", "primary");
    let rows = persist_context_packet_record(&db.pool, &record)
        .await
        .expect("first persist");
    assert_eq!(rows, 1);

    let replay_rows = persist_context_packet_record(&db.pool, &record)
        .await
        .expect("exact replay");
    assert_eq!(replay_rows, 0);

    let cross_scope = record_for_scope("packet-prd17b-001", "tenant-b", "project-b", "primary");
    assert!(matches!(
        persist_context_packet_record(&db.pool, &cross_scope).await,
        Err(ContextPacketPostgresError::UnsafeReplay { .. })
    ));

    let mut mutated = record_for_scope("packet-prd17b-001", "tenant-a", "project-a", "primary");
    mutated.persistence_status = PacketPersistenceStatus::Persisted;
    assert!(matches!(
        persist_context_packet_record(&db.pool, &mutated).await,
        Err(ContextPacketPostgresError::UnsafeReplay { .. })
    ));

    let (tenant_id, persistence_status) = sqlx::query_as::<_, (String, String)>(
        "SELECT tenant_id, persistence_status FROM dagdb_context_packet_records \
         WHERE packet_id = $1",
    )
    .bind("packet-prd17b-001")
    .fetch_one(&db.pool)
    .await
    .expect("load persisted packet row");
    assert_eq!(tenant_id, "tenant-a");
    assert_eq!(persistence_status, "proof_bound");
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!(
                "skipping context packet postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set"
            );
            return None;
        };
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut admin = PgConnection::connect(&database_url)
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut admin)
        .await
        .expect("drop existing context packet test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create context packet test schema");

        let separator = if database_url.contains('?') { '&' } else { '?' };
        let scoped_url =
            format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&scoped_url)
            .await
            .expect("connect context packet test pool");
        sqlx::raw_sql(DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply PRD17B context packet schema");
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
                    .expect("connect for context packet cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop context packet test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}
