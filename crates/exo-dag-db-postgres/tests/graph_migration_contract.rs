#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::process;

use exo_dag_db_postgres::postgres::{DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL};
use sqlx::{Connection, PgConnection, Row};

const GRAPH_TABLES: &[&str] = &[
    "dagdb_graph_canonicalization_decisions",
    "dagdb_graph_edge_tombstones",
    "dagdb_graph_edges",
    "dagdb_graph_layer_edges",
    "dagdb_graph_layer_memberships",
    "dagdb_graph_layers",
    "dagdb_graph_nodes",
    "dagdb_graph_placement_traces",
    "dagdb_graph_route_invalidations",
    "dagdb_graph_similarity_results",
    "dagdb_graph_views",
];

const GRAPH_INDEXES: &[&str] = &[
    "idx_dagdb_graph_nodes_memory",
    "idx_dagdb_graph_edges_from_kind",
    "idx_dagdb_graph_edge_tombstones_edge",
    "idx_dagdb_graph_edge_tombstones_created",
    "idx_dagdb_graph_layers_path",
    "idx_dagdb_graph_layers_parent_layer",
    "idx_dagdb_graph_layers_parent_graph_node",
    "idx_dagdb_graph_layer_memberships_layer_node",
    "idx_dagdb_graph_layer_memberships_graph_node",
    "idx_dagdb_graph_layer_edges_from",
    "idx_dagdb_graph_layer_edges_to",
    "idx_dagdb_graph_layer_edges_kind",
    "idx_dagdb_graph_similarity_candidate",
    "idx_dagdb_graph_canon_input",
    "idx_dagdb_graph_views_root_style",
    "idx_dagdb_graph_route_invalidations_route",
];

#[tokio::test]
async fn graph_schema_matches_additive_contract() {
    let Some(mut db) = TestDb::maybe_new("graph_migration").await else {
        return;
    };
    db.apply_schema().await;
    db.apply_schema().await;

    assert_graph_tables(&mut db.conn).await;
    assert_graph_columns(&mut db.conn).await;
    assert_graph_constraints(&mut db.conn).await;
    assert_graph_indexes(&mut db.conn).await;
}

#[tokio::test]
async fn graph_migration_rolls_back_without_partial_tables() {
    let Some(mut db) = TestDb::maybe_new("graph_rollback").await else {
        return;
    };
    sqlx::raw_sql("BEGIN")
        .execute(&mut db.conn)
        .await
        .expect("begin graph migration rollback test");
    db.set_search_path().await;
    sqlx::raw_sql(DAGDB_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply base DAG DB schema inside rollback");
    sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply graph schema inside rollback");
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut db.conn)
        .await
        .expect("rollback graph schema transaction");

    let table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name LIKE 'dagdb_graph_%'",
    )
    .bind(&db.schema)
    .fetch_one(&mut db.conn)
    .await
    .expect("count graph tables after rollback");
    assert_eq!(table_count, 0);
}

async fn assert_graph_tables(conn: &mut PgConnection) {
    let mut actual = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'dagdb_graph_%' \
         ORDER BY table_name",
    )
    .fetch_all(conn)
    .await
    .expect("query graph tables");
    actual.sort();
    assert_eq!(actual, GRAPH_TABLES);
}

async fn assert_graph_columns(conn: &mut PgConnection) {
    for (table, columns) in expected_columns() {
        let actual = sqlx::query_scalar::<_, String>(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 \
             ORDER BY ordinal_position",
        )
        .bind(table)
        .fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("query columns for {table}: {err}"));
        assert_eq!(actual, columns, "column names for {table}");
    }
}

async fn assert_graph_constraints(conn: &mut PgConnection) {
    let constraints = sqlx::query(
        "SELECT rel.relname AS table_name, pg_get_constraintdef(con.oid) AS definition \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid = con.conrelid \
         JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
         WHERE ns.nspname = current_schema() AND rel.relname LIKE 'dagdb_graph_%'",
    )
    .fetch_all(conn)
    .await
    .expect("query graph constraints");
    for (table, snippet) in expected_constraint_snippets() {
        assert!(
            constraints.iter().any(|row| {
                row.get::<String, _>("table_name") == *table
                    && row.get::<String, _>("definition").contains(snippet)
            }),
            "missing graph constraint snippet {snippet:?} on {table}"
        );
    }
}

async fn assert_graph_indexes(conn: &mut PgConnection) {
    let actual = sqlx::query_scalar::<_, String>(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = current_schema() AND indexname LIKE 'idx_dagdb_graph_%'",
    )
    .fetch_all(conn)
    .await
    .expect("query graph indexes");
    for index in GRAPH_INDEXES {
        assert!(
            actual.iter().any(|actual| actual == index),
            "missing {index}"
        );
    }
}

fn expected_columns() -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "dagdb_graph_nodes",
            vec![
                "graph_node_id",
                "tenant_id",
                "namespace",
                "memory_id",
                "graph_style",
                "node_kind",
                "canonical_memory_id",
                "catalog_path",
                "metadata",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
        (
            "dagdb_graph_edge_tombstones",
            vec![
                "tombstone_id",
                "tenant_id",
                "namespace",
                "prior_edge_id",
                "tombstone_reason",
                "recommended_action",
                "receipt_hash",
                "idempotency_key",
                "created_at_physical_ms",
                "created_at_logical",
                "tombstone_body",
            ],
        ),
        (
            "dagdb_graph_edges",
            vec![
                "graph_edge_id",
                "tenant_id",
                "namespace",
                "graph_style",
                "from_memory_id",
                "to_memory_id",
                "edge_kind",
                "receipt_hash",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
        (
            "dagdb_graph_layer_edges",
            vec![
                "layer_edge_id",
                "tenant_id",
                "namespace",
                "graph_style",
                "from_layer_id",
                "to_layer_id",
                "edge_kind",
                "receipt_hash",
                "metadata",
                "created_at_physical_ms",
                "created_at_logical",
                "updated_at_physical_ms",
                "updated_at_logical",
            ],
        ),
        (
            "dagdb_graph_layer_memberships",
            vec![
                "layer_membership_id",
                "tenant_id",
                "namespace",
                "layer_id",
                "graph_node_id",
                "graph_style",
                "membership_role",
                "local_node_rank",
                "metadata",
                "created_at_physical_ms",
                "created_at_logical",
                "updated_at_physical_ms",
                "updated_at_logical",
            ],
        ),
        (
            "dagdb_graph_layers",
            vec![
                "layer_id",
                "tenant_id",
                "namespace",
                "root_memory_id",
                "parent_layer_id",
                "parent_graph_node_id",
                "layer_depth",
                "layer_kind",
                "graph_style",
                "layer_path",
                "metadata",
                "created_at_physical_ms",
                "created_at_logical",
                "updated_at_physical_ms",
                "updated_at_logical",
                // PRD-D2 S1: nullable aggregate root summary column, appended
                // last by ALTER TABLE ADD COLUMN (highest ordinal position).
                "aggregate_summary",
            ],
        ),
        (
            "dagdb_graph_similarity_results",
            vec![
                "similarity_result_id",
                "tenant_id",
                "namespace",
                "candidate_memory_id",
                "matched_memory_id",
                "similarity_type",
                "similarity_bp",
                "matched_fields",
                "reason",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
        (
            "dagdb_graph_canonicalization_decisions",
            vec![
                "decision_id",
                "tenant_id",
                "namespace",
                "input_memory_id",
                "canonical_memory_id",
                "matched_memory_ids",
                "decision_kind",
                "decision_reason",
                "confidence_bp",
                "risk_class",
                "validator_status",
                "required_edges_to_create",
                "receipt_hash",
                "receipt_intent",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
        (
            "dagdb_graph_views",
            vec![
                "view_id",
                "tenant_id",
                "namespace",
                "graph_style",
                "source_root_id",
                "included_node_ids",
                "included_edge_ids",
                "view_type",
                "topological_order",
                "transitive_reduction_edges",
                "omitted_edges",
                "reason_edges_omitted",
                "source_records_hash",
                "stale",
                "created_at_physical_ms",
                "created_at_logical",
                "refreshed_at_physical_ms",
                "refreshed_at_logical",
            ],
        ),
        (
            "dagdb_graph_placement_traces",
            vec![
                "placement_trace_id",
                "tenant_id",
                "namespace",
                "input_memory_id",
                "trace_steps",
                "completed",
                "created_at_physical_ms",
                "created_at_logical",
            ],
        ),
        (
            "dagdb_graph_route_invalidations",
            vec![
                "invalidation_id",
                "tenant_id",
                "namespace",
                "route_id",
                "affected_memory_ids",
                "trigger_type",
                "triggering_receipt_id",
                "prior_route_status",
                "new_route_status",
                "invalidation_reason",
                "created_at_physical_ms",
                "created_at_logical",
                "validator_id",
                "validation_report_id",
                "receipt_hash",
                "receipt_intent",
            ],
        ),
    ]
    .into_iter()
    .map(|(table, columns)| {
        (
            table,
            columns
                .into_iter()
                .map(std::borrow::ToOwned::to_owned)
                .collect(),
        )
    })
    .collect()
}

fn expected_constraint_snippets() -> &'static [(&'static str, &'static str)] {
    &[
        ("dagdb_graph_nodes", "graph_style = ANY"),
        ("dagdb_graph_nodes", "node_kind = ANY"),
        ("dagdb_graph_edges", "edge_kind = ANY"),
        ("dagdb_graph_edge_tombstones", "recommended_action = ANY"),
        ("dagdb_graph_layers", "layer_kind = ANY"),
        ("dagdb_graph_layers", "graph_style = ANY"),
        ("dagdb_graph_layers", "layer_depth >= 0"),
        ("dagdb_graph_layer_memberships", "membership_role = ANY"),
        ("dagdb_graph_layer_memberships", "local_node_rank >= 0"),
        ("dagdb_graph_layer_edges", "edge_kind = ANY"),
        ("dagdb_graph_similarity_results", "similarity_bp >= 0"),
        (
            "dagdb_graph_canonicalization_decisions",
            "confidence_bp >= 0",
        ),
        ("dagdb_graph_views", "view_type = ANY"),
        ("dagdb_graph_route_invalidations", "trigger_type = ANY"),
        ("dagdb_graph_route_invalidations", "new_route_status = ANY"),
    ]
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
                "skipping graph migration postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set"
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
        .expect("drop existing graph test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut conn)
            .await
            .expect("create graph test schema");
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
        .expect("set graph test search_path");
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
            let runtime = tokio::runtime::Runtime::new().expect("create graph cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for graph cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop graph test schema");
            });
        })
        .join()
        .expect("join graph cleanup thread");
    }
}
