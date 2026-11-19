#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::process;

use exo_dag_db_postgres::postgres::{DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL};
use serde_json::json;
use sqlx::{Connection, PgConnection};

#[tokio::test]
async fn graph_records_persist_without_rewriting_source_of_truth() {
    let Some(mut db) = TestDb::maybe_new("graph_persistence").await else {
        return;
    };
    db.apply_schema().await;
    seed_receipts_memory_and_route(&mut db.conn).await;

    insert_graph_records(&mut db.conn)
        .await
        .expect("insert graph organization records");

    let graph_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_edges")
        .fetch_one(&mut db.conn)
        .await
        .expect("count graph edges");
    let route_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_route_receipts")
        .fetch_one(&mut db.conn)
        .await
        .expect("count route records");
    let invalidation_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_route_invalidations")
            .fetch_one(&mut db.conn)
            .await
            .expect("count graph route invalidations");
    let source_receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_receipts")
        .fetch_one(&mut db.conn)
        .await
        .expect("count source receipts");

    assert_eq!(graph_count, 1);
    assert_eq!(route_count, 1, "route history is preserved, not deleted");
    assert_eq!(invalidation_count, 1);
    assert_eq!(
        source_receipt_count, 3,
        "graph rows reference existing receipts only"
    );
}

#[tokio::test]
async fn graph_constraints_fail_closed_for_invalid_route_invalidation() {
    let Some(mut db) = TestDb::maybe_new("graph_invalid_invalidation").await else {
        return;
    };
    db.apply_schema().await;
    seed_receipts_memory_and_route(&mut db.conn).await;

    let error = sqlx::query(
        "INSERT INTO dagdb_graph_route_invalidations \
         (invalidation_id, tenant_id, namespace, route_id, affected_memory_ids, trigger_type, triggering_receipt_id, prior_route_status, new_route_status, invalidation_reason, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, '[]'::jsonb, 'permission_changed', $3, 'active', 'deleted', 'bad status', 10, 0)",
    )
    .bind(bytes(80))
    .bind(bytes(81))
    .bind(bytes(3))
    .execute(&mut db.conn)
    .await
    .expect_err("invalid route invalidation status must fail closed");
    assert!(
        error.to_string().contains("new_route_status")
            || error.to_string().contains("route_invalidations"),
        "unexpected invalidation error: {error}"
    );
}

#[tokio::test]
async fn graph_view_stale_flag_is_rebuildable_not_destructive() {
    let Some(mut db) = TestDb::maybe_new("graph_view_stale").await else {
        return;
    };
    db.apply_schema().await;
    seed_receipts_memory_and_route(&mut db.conn).await;
    insert_graph_records(&mut db.conn)
        .await
        .expect("insert graph organization records");

    sqlx::query("UPDATE dagdb_graph_views SET stale = true WHERE view_id = $1")
        .bind(bytes(70))
        .execute(&mut db.conn)
        .await
        .expect("mark graph view stale");
    sqlx::query(
        "UPDATE dagdb_graph_views \
         SET stale = false, source_records_hash = $1, refreshed_at_physical_ms = 20, refreshed_at_logical = 0 \
         WHERE view_id = $2",
    )
    .bind(bytes(71))
    .bind(bytes(70))
    .execute(&mut db.conn)
    .await
    .expect("regenerate graph view from source records");

    let edge_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_edges")
        .fetch_one(&mut db.conn)
        .await
        .expect("count graph edges after view regeneration");
    let stale: bool = sqlx::query_scalar("SELECT stale FROM dagdb_graph_views WHERE view_id = $1")
        .bind(bytes(70))
        .fetch_one(&mut db.conn)
        .await
        .expect("load regenerated graph view");
    assert_eq!(
        edge_count, 1,
        "view regeneration does not delete graph edges"
    );
    assert!(!stale);
}

#[tokio::test]
async fn graph_edge_tombstones_are_durable_and_non_destructive() {
    let Some(mut db) = TestDb::maybe_new("graph_edge_tombstone").await else {
        return;
    };
    db.apply_schema().await;
    seed_receipts_memory_and_route(&mut db.conn).await;
    insert_graph_records(&mut db.conn)
        .await
        .expect("insert graph organization records");

    insert_graph_edge_tombstone(&mut db.conn)
        .await
        .expect("insert graph edge tombstone");
    insert_graph_edge_tombstone(&mut db.conn)
        .await
        .expect("replay graph edge tombstone");

    let graph_count: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_edges")
        .fetch_one(&mut db.conn)
        .await
        .expect("count graph edges after tombstone");
    let tombstone_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_edge_tombstones")
            .fetch_one(&mut db.conn)
            .await
            .expect("count graph edge tombstones");
    let tombstone_receipt: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt_hash FROM dagdb_graph_edge_tombstones WHERE prior_edge_id = $1",
    )
    .bind(bytes(51))
    .fetch_one(&mut db.conn)
    .await
    .expect("load tombstone receipt");

    assert_eq!(
        graph_count, 1,
        "tombstoning must not delete graph edge rows"
    );
    assert_eq!(tombstone_count, 1, "tombstone insert must be idempotent");
    assert_eq!(tombstone_receipt, bytes(3));
}

#[tokio::test]
async fn graph_edge_tombstone_requires_existing_receipt() {
    let Some(mut db) = TestDb::maybe_new("graph_edge_tombstone_receipt_fk").await else {
        return;
    };
    db.apply_schema().await;
    seed_receipts_memory_and_route(&mut db.conn).await;
    insert_graph_records(&mut db.conn)
        .await
        .expect("insert graph organization records");

    let error = sqlx::query(
        "INSERT INTO dagdb_graph_edge_tombstones \
         (tombstone_id, tenant_id, namespace, prior_edge_id, tombstone_reason, recommended_action, receipt_hash, idempotency_key, created_at_physical_ms, created_at_logical, tombstone_body) \
         VALUES ($1, 'tenant-a', 'default', $2, 'missing_receipt_hash', 'tombstone', $3, 'graph-edge-tombstone-missing-receipt', 10, 0, '{}'::jsonb)",
    )
    .bind(bytes(91))
    .bind(bytes(51))
    .bind(bytes(99))
    .execute(&mut db.conn)
    .await
    .expect_err("tombstone receipt_hash must reference an existing receipt");
    assert!(
        error.to_string().contains("receipt_hash") || error.to_string().contains("foreign key"),
        "unexpected tombstone receipt error: {error}"
    );
}

async fn seed_receipts_memory_and_route(conn: &mut PgConnection) {
    insert_receipt(conn, bytes(1), bytes(11), "memory", "intake_created").await;
    insert_receipt(conn, bytes(2), bytes(41), "route", "route_created").await;
    insert_receipt_with_link(
        conn,
        bytes(3),
        bytes(41),
        "route",
        "route_invalidated",
        2,
        bytes(2),
    )
    .await;
    insert_memory(conn, bytes(11), bytes(1), bytes(21), bytes(22)).await;
    insert_memory(conn, bytes(12), bytes(1), bytes(23), bytes(24)).await;
    insert_route(conn, bytes(41), bytes(2)).await;
}

async fn insert_graph_records(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dagdb_graph_nodes \
         (graph_node_id, tenant_id, namespace, memory_id, graph_style, node_kind, canonical_memory_id, metadata, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, 'canonical_memory_graph', 'canonical', $2, '{}'::jsonb, 10, 0)",
    )
    .bind(bytes(50))
    .bind(bytes(11))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_edges \
         (graph_edge_id, tenant_id, namespace, graph_style, from_memory_id, to_memory_id, edge_kind, receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'similarity_overlay_graph', $2, $3, 'near_duplicate_of', $4, 10, 0)",
    )
    .bind(bytes(51))
    .bind(bytes(12))
    .bind(bytes(11))
    .bind(bytes(1))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_similarity_results \
         (similarity_result_id, tenant_id, namespace, candidate_memory_id, matched_memory_id, similarity_type, similarity_bp, matched_fields, reason, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, 'near_duplicate', 9000, $4, 'summary overlap', 10, 0)",
    )
    .bind(bytes(60))
    .bind(bytes(12))
    .bind(bytes(11))
    .bind(json!(["summary"]))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_canonicalization_decisions \
         (decision_id, tenant_id, namespace, input_memory_id, canonical_memory_id, matched_memory_ids, decision_kind, decision_reason, confidence_bp, risk_class, validator_status, required_edges_to_create, receipt_hash, receipt_intent, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, $4, 'near_duplicate', 'summary overlap', 9000, 'R1', 'passed', $5, $6, 'placement_validated', 10, 0)",
    )
    .bind(bytes(61))
    .bind(bytes(12))
    .bind(bytes(11))
    .bind(json!([hex_bytes(11)]))
    .bind(json!([{"from_memory_id": hex_bytes(12), "to_memory_id": hex_bytes(11), "edge_kind": "near_duplicate_of"}]))
    .bind(bytes(1))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_views \
         (view_id, tenant_id, namespace, graph_style, source_root_id, included_node_ids, included_edge_ids, view_type, topological_order, transitive_reduction_edges, omitted_edges, reason_edges_omitted, source_records_hash, stale, created_at_physical_ms, created_at_logical, refreshed_at_physical_ms, refreshed_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'routing_view_graph', $2, $3, $4, 'routing_view', $3, '[]'::jsonb, '[]'::jsonb, $5, $6, false, 10, 0, 10, 0)",
    )
    .bind(bytes(70))
    .bind(bytes(11))
    .bind(json!([hex_bytes(11), hex_bytes(12)]))
    .bind(json!([hex_bytes(51)]))
    .bind(json!(["transitive edge omitted from derived view only"]))
    .bind(bytes(9))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_placement_traces \
         (placement_trace_id, tenant_id, namespace, input_memory_id, trace_steps, completed, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, true, 10, 0)",
    )
    .bind(bytes(72))
    .bind(bytes(12))
    .bind(json!([
        "source_verification",
        "risk_classification",
        "identity_assignment",
        "exact_duplicate_check",
        "similarity_overlay_check",
        "canonicalization_decision",
        "metadata_attachment",
        "semantic_catalog_graph_placement",
        "provenance_receipt_dag_placement",
        "canonical_memory_graph_update",
        "dependency_dag_update",
        "contradiction_supersession_graph_update",
        "validation",
        "receipt_writeback",
        "routing_view_graph_refresh",
        "route_invalidation",
        "query_exposure"
    ]))
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dagdb_graph_route_invalidations \
         (invalidation_id, tenant_id, namespace, route_id, affected_memory_ids, trigger_type, triggering_receipt_id, prior_route_status, new_route_status, invalidation_reason, created_at_physical_ms, created_at_logical, validator_id, receipt_hash) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, 'superseded', $4, 'active', 'superseded', 'memory superseded', 10, 0, 'did:exo:validator', $4)",
    )
    .bind(bytes(73))
    .bind(bytes(41))
    .bind(json!([hex_bytes(12)]))
    .bind(bytes(3))
    .execute(conn)
    .await?;

    Ok(())
}

async fn insert_graph_edge_tombstone(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dagdb_graph_edge_tombstones \
         (tombstone_id, tenant_id, namespace, prior_edge_id, tombstone_reason, recommended_action, receipt_hash, idempotency_key, created_at_physical_ms, created_at_logical, tombstone_body) \
         VALUES ($1, 'tenant-a', 'default', $2, 'negative_quality_delta', 'tombstone', $3, 'graph-edge-tombstone-fixture', 10, 0, $4) \
         ON CONFLICT (tenant_id, namespace, prior_edge_id, tombstone_reason) DO NOTHING",
    )
    .bind(bytes(90))
    .bind(bytes(51))
    .bind(bytes(3))
    .bind(json!({"prior_edge_id": hex_bytes(51), "physical_delete_count": 0}))
    .execute(conn)
    .await?;
    Ok(())
}

async fn insert_receipt(
    conn: &mut PgConnection,
    receipt_hash: Vec<u8>,
    subject_id: Vec<u8>,
    kind: &str,
    event_type: &str,
) {
    insert_receipt_with_link(
        conn,
        receipt_hash,
        subject_id,
        kind,
        event_type,
        1,
        bytes(0),
    )
    .await;
}

async fn insert_receipt_with_link(
    conn: &mut PgConnection,
    receipt_hash: Vec<u8>,
    subject_id: Vec<u8>,
    kind: &str,
    event_type: &str,
    seq: i64,
    prev_receipt_hash: Vec<u8>,
) {
    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', $2, $3, $4, $5, $6, 'did:example:actor', 1, 0, $7, '{}'::jsonb, 1, 0)",
    )
    .bind(receipt_hash)
    .bind(kind)
    .bind(subject_id)
    .bind(prev_receipt_hash)
    .bind(seq)
    .bind(event_type)
    .bind(bytes(9))
    .execute(conn)
    .await
    .expect("insert graph fixture receipt");
}

async fn insert_memory(
    conn: &mut PgConnection,
    memory_id: Vec<u8>,
    latest_receipt_hash: Vec<u8>,
    payload_hash: Vec<u8>,
    source_hash: Vec<u8>,
) {
    let metadata = json!({
        "decision": "allow",
        "text": "safe graph memory",
        "redaction_codes": [],
        "original_hash": "caac13844969e521bb8bfcf8bc706ad54bcce3e3f260368eda31bdb0542d00e1",
        "truncated": false,
        "byte_len": 17
    });
    sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, owner_did, controller_did, submitted_by_did, title, summary, keywords, risk_class, risk_bp, status, validation_status, dag_finality_status, latest_receipt_hash, created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'summary', 'generated', 'retrieval', $2, $3, 'did:example:owner', 'did:example:controller', 'did:example:submitter', $4, $4, '[]'::jsonb, 'R1', 1000, 'routable', 'passed', 'committed', $5, 1, 0, 1, 0)",
    )
    .bind(memory_id)
    .bind(payload_hash)
    .bind(source_hash)
    .bind(metadata)
    .bind(latest_receipt_hash)
    .execute(conn)
    .await
    .expect("insert graph fixture memory");
}

async fn insert_route(conn: &mut PgConnection, route_id: Vec<u8>, latest_receipt_hash: Vec<u8>) {
    sqlx::query(
        "INSERT INTO dagdb_route_receipts \
         (route_id, tenant_id, namespace, requesting_agent_did, task_signature_hash, approved_scope_hash, candidate_memory_ids, selected_memory_ids, route_score_bp, token_budget, token_estimate, risk_bp, status, validation_status, dag_finality_status, stale_at_physical_ms, stale_at_logical, latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'did:example:agent', $2, $3, $4, $5, 9000, 4096, 512, 1000, 'active', 'passed', 'committed', 86400000, 0, $6, 1, 0)",
    )
    .bind(route_id)
    .bind(bytes(42))
    .bind(bytes(43))
    .bind(json!([hex_bytes(11), hex_bytes(12)]))
    .bind(json!([hex_bytes(11)]))
    .bind(latest_receipt_hash)
    .execute(conn)
    .await
    .expect("insert graph fixture route");
}

fn bytes(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn hex_bytes(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32)
}

struct TestDb {
    conn: PgConnection,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!(
                "skipping graph persistence postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set"
            );
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
        .expect("drop existing graph persistence test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut conn)
            .await
            .expect("create graph persistence test schema");
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
        .expect("set graph persistence search_path");
    }

    async fn apply_schema(&mut self) {
        self.set_search_path().await;
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply base DAG DB schema");
        sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply graph schema");
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let schema = self.schema.clone();
        let database_url = self.database_url.clone();
        std::thread::spawn(move || {
            let runtime =
                tokio::runtime::Runtime::new().expect("create graph persistence cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for graph persistence cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop graph persistence test schema");
            });
        })
        .join()
        .expect("join graph persistence cleanup thread");
    }
}
