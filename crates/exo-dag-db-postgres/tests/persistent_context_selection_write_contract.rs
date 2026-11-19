#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use exo_dag_db_api::{DagDbGraphContextSelectionRequest, DagDbGraphContextSelectionStatus};
use exo_dag_db_postgres::{
    DomainError, build_persistent_graph_context_packet, build_persistent_graph_context_selection,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
    },
    persist_context_packet_receipt_to_db, persist_usage_event_to_db,
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL,
        kg_import::persist_kg_import_report,
    },
};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var(KG_IMPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping persistent_context_selection_write postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!(
            "dagdb_context_selection_write_{label}_{}",
            std::process::id()
        );
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

        let scoped_url = database_url_with_search_path(&database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&scoped_url)
            .await
            .expect("connect scoped Postgres pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB schema");
        sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB graph schema");
        sqlx::raw_sql(DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB telemetry-facet node_type schema");
        Some(Self {
            admin_pool,
            pool,
            schema,
        })
    }

    async fn cleanup(self) {
        self.pool.close().await;
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

#[tokio::test]
async fn persist_usage_event_writes_and_replays_idempotently() {
    let Some(db) = TestDb::new("usage_event").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    assert!(
        !selection.selection.selected_memory_refs.is_empty(),
        "fixture should select memories"
    );

    let first = persist_usage_event_to_db(&db.pool, &selection.selection)
        .await
        .expect("first usage event write");
    assert_eq!(first.tenant_id, "tenant-test");
    assert_eq!(first.namespace, "dag-db");
    assert!(!first.receipt_hash.is_empty());
    assert!(!first.replayed);
    assert!(first.inserted_rows > 0);

    let usage_row_count = usage_event_row_count(&db.pool, "tenant-test", "dag-db").await;
    assert_eq!(usage_row_count, 1, "exactly one usage-event row expected");

    // PRD-D4 structural-home contract: the usage-event write lands in the
    // telemetry facet (node_type='usage_event'), NOT as a knowledge 'excerpt'.
    assert_eq!(
        knowledge_excerpt_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "usage-event telemetry must not be written as a knowledge excerpt"
    );

    let second = persist_usage_event_to_db(&db.pool, &selection.selection)
        .await
        .expect("second usage event write");
    assert!(second.replayed);
    assert_eq!(second.receipt_hash, first.receipt_hash);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        1,
        "idempotent replay must not insert duplicate usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_cross_scope_memory_refs() {
    let Some(db) = TestDb::new("scope_mismatch").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    let mut mismatched = selection.selection.clone();
    mismatched.tenant_id = "missing-tenant".to_owned();

    let error = persist_usage_event_to_db(&db.pool, &mismatched)
        .await
        .expect_err("cross-scope write must fail closed");
    assert!(
        matches!(error, DomainError::TenantScopeMismatch { .. }),
        "expected tenant scope mismatch, got {error:?}"
    );

    assert_eq!(
        usage_event_row_count(&db.pool, "missing-tenant", "dag-db").await,
        0,
        "failed write must not leak rows"
    );
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed write must not leak rows into fixture scope"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_writes_and_replays_idempotently() {
    let Some(db) = TestDb::new("packet_receipt").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    assert!(
        !packet_result.packet.selected_memory_refs.is_empty(),
        "fixture should select memories"
    );

    let first = persist_context_packet_receipt_to_db(&db.pool, &packet_result.packet)
        .await
        .expect("first packet receipt write");
    assert_eq!(first.tenant_id, "tenant-test");
    assert_eq!(first.namespace, "dag-db");
    assert!(!first.receipt_hash.is_empty());
    assert!(!first.replayed);
    assert!(first.inserted_rows > 0);

    let packet_row_count = context_packet_row_count(&db.pool, "tenant-test", "dag-db").await;
    assert_eq!(
        packet_row_count, 1,
        "exactly one context-packet row expected"
    );

    let second = persist_context_packet_receipt_to_db(&db.pool, &packet_result.packet)
        .await
        .expect("second packet receipt write");
    assert!(second.replayed);
    assert_eq!(second.receipt_hash, first.receipt_hash);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        1,
        "idempotent replay must not insert duplicate packet rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_idempotency_replay_mismatch() {
    let Some(db) = TestDb::new("usage_event_replay_mismatch").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    let original = selection.selection.clone();
    persist_usage_event_to_db(&db.pool, &original)
        .await
        .expect("first usage event write");

    let mut mismatched = original.clone();
    mismatched.selection_status = DagDbGraphContextSelectionStatus::Empty;

    let error = persist_usage_event_to_db(&db.pool, &mismatched)
        .await
        .expect_err("mismatched replay must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        1,
        "mismatch must not insert duplicate usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_idempotency_replay_mismatch() {
    let Some(db) = TestDb::new("packet_receipt_replay_mismatch").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    let original = packet_result.packet.clone();
    persist_context_packet_receipt_to_db(&db.pool, &original)
        .await
        .expect("first packet receipt write");

    let mut mismatched = original.clone();
    mismatched.task = "changed task body".into();

    let error = persist_context_packet_receipt_to_db(&db.pool, &mismatched)
        .await
        .expect_err("mismatched packet replay must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        1,
        "mismatch must not insert duplicate packet rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_missing_selected_memory() {
    let Some(db) = TestDb::new("usage_event_missing_memory").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    let mut missing_memory = selection.selection.clone();
    missing_memory.selected_memory_refs[0].memory_id = h(0xff);

    let error = persist_usage_event_to_db(&db.pool, &missing_memory)
        .await
        .expect_err("missing selected memory must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed write must not leak usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_missing_selected_graph_edge() {
    let Some(db) = TestDb::new("usage_event_missing_edge").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    assert!(
        !selection.selection.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut missing_edge = selection.selection.clone();
    missing_edge.selected_graph_edges[0].graph_edge_id = h(0xff);

    let error = persist_usage_event_to_db(&db.pool, &missing_edge)
        .await
        .expect_err("missing selected graph edge must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed write must not leak usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_over_budget_selected_graph_edges() {
    let Some(db) = TestDb::new("usage_event_over_budget_edges").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    assert!(
        !selection.selection.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut over_budget = selection.selection.clone();
    let edge = over_budget.selected_graph_edges[0].clone();
    over_budget.selected_graph_edges = vec![edge; 13];

    let error = persist_usage_event_to_db(&db.pool, &over_budget)
        .await
        .expect_err("over-budget selected graph edges must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed write must not leak usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_selected_graph_edge_outside_selected_memories() {
    let Some(db) = TestDb::new("usage_event_edge_endpoint_not_selected").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    assert!(
        !selection.selection.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut endpoint_missing = selection.selection.clone();
    let missing_endpoint = endpoint_missing.selected_graph_edges[0]
        .to_memory_id
        .clone();
    endpoint_missing
        .selected_memory_refs
        .retain(|memory| memory.memory_id != missing_endpoint);

    let error = persist_usage_event_to_db(&db.pool, &endpoint_missing)
        .await
        .expect_err("selected graph edge endpoint outside selected memories must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed write must not leak usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_cross_scope_memory_refs() {
    let Some(db) = TestDb::new("packet_scope_mismatch").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    let mut mismatched = packet_result.packet.clone();
    mismatched.tenant_id = "missing-tenant".to_owned();

    let error = persist_context_packet_receipt_to_db(&db.pool, &mismatched)
        .await
        .expect_err("cross-scope packet receipt must fail closed");
    assert!(
        matches!(error, DomainError::TenantScopeMismatch { .. }),
        "expected tenant scope mismatch, got {error:?}"
    );
    assert_eq!(
        context_packet_row_count(&db.pool, "missing-tenant", "dag-db").await,
        0,
        "failed write must not leak packet rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_usage_event_rejects_corrupt_idempotency_response_body() {
    let Some(db) = TestDb::new("usage_event_corrupt_idempotency").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection");
    let event = selection.selection.clone();
    let first = persist_usage_event_to_db(&db.pool, &event)
        .await
        .expect("first usage event write");

    sqlx::query(
        "UPDATE dagdb_idempotency_keys SET response_body = '\"not-an-object\"'::jsonb \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3",
    )
    .bind(&event.tenant_id)
    .bind(&event.namespace)
    .bind(
        exo_dag_db_postgres::postgres::kg_context_selection_write::CONTEXT_SELECTION_USAGE_EVENT_ROUTE_NAME,
    )
    .execute(&db.pool)
    .await
    .expect("corrupt cached idempotency body");

    let error = persist_usage_event_to_db(&db.pool, &event)
        .await
        .expect_err("corrupt idempotency body must fail closed");
    assert!(
        matches!(error, DomainError::HashMaterial { .. }),
        "expected hash material error, got {error:?}"
    );
    assert_eq!(first.receipt_hash.len(), 64);
    assert_eq!(
        usage_event_row_count(&db.pool, "tenant-test", "dag-db").await,
        1,
        "corrupt replay must not insert duplicate usage-event rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_missing_selected_memory() {
    let Some(db) = TestDb::new("packet_missing_memory").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    let mut missing_memory = packet_result.packet.clone();
    missing_memory.selected_memory_refs[0].memory_id = h(0xff);

    let error = persist_context_packet_receipt_to_db(&db.pool, &missing_memory)
        .await
        .expect_err("missing selected memory must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed packet write must not leak rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_missing_selected_graph_edge() {
    let Some(db) = TestDb::new("packet_missing_edge").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    assert!(
        !packet_result.packet.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut missing_edge = packet_result.packet.clone();
    missing_edge.selected_graph_edges[0].graph_edge_id = h(0xff);

    let error = persist_context_packet_receipt_to_db(&db.pool, &missing_edge)
        .await
        .expect_err("missing selected graph edge must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed packet write must not leak rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_over_budget_selected_graph_edges() {
    let Some(db) = TestDb::new("packet_over_budget_edges").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    assert!(
        !packet_result.packet.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut over_budget = packet_result.packet.clone();
    let edge = over_budget.selected_graph_edges[0].clone();
    over_budget.selected_graph_edges = vec![edge; 13];

    let error = persist_context_packet_receipt_to_db(&db.pool, &over_budget)
        .await
        .expect_err("over-budget packet selected graph edges must fail closed");
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed packet write must not leak rows"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn persist_context_packet_receipt_rejects_selected_graph_edge_outside_selected_memories() {
    let Some(db) = TestDb::new("packet_edge_endpoint_not_selected").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let packet_result = build_persistent_graph_context_packet(&db.pool, &base_packet_request())
        .await
        .expect("build packet");
    assert!(
        !packet_result.packet.selected_graph_edges.is_empty(),
        "fixture should select graph edges"
    );
    let mut endpoint_missing = packet_result.packet.clone();
    let missing_endpoint = endpoint_missing.selected_graph_edges[0]
        .to_memory_id
        .clone();
    endpoint_missing
        .selected_memory_refs
        .retain(|memory| memory.memory_id != missing_endpoint);

    let error = persist_context_packet_receipt_to_db(&db.pool, &endpoint_missing)
        .await
        .expect_err(
            "packet selected graph edge endpoint outside selected memories must fail closed",
        );
    assert_eq!(error, DomainError::ValidationFailed);
    assert_eq!(
        context_packet_row_count(&db.pool, "tenant-test", "dag-db").await,
        0,
        "failed packet write must not leak rows"
    );

    db.cleanup().await;
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn base_selection_request() -> DagDbGraphContextSelectionRequest {
    DagDbGraphContextSelectionRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        request_id: "req-persistent-context-write-1".to_owned(),
        task: "Explain dag-db index and project brief context for governed memory".to_owned(),
        task_hash: h(0xaa),
        token_budget: 2_000,
        max_memory_refs: 8,
        catalog_hints: vec!["dag-db".to_owned()],
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

fn base_packet_request() -> exo_dag_db_api::DagDbGraphContextPacketBuildRequest {
    let selection_request = base_selection_request();
    exo_dag_db_api::DagDbGraphContextPacketBuildRequest {
        tenant_id: selection_request.tenant_id.clone(),
        namespace: selection_request.namespace.clone(),
        request_id: selection_request.request_id.clone(),
        task: selection_request.task.clone(),
        task_hash: selection_request.task_hash.clone(),
        audit_id: "audit-persistent-context-write-1".to_owned(),
        token_budget: selection_request.token_budget,
        selection: exo_dag_db_api::DagDbGraphContextSelectionResponse {
            tenant_id: selection_request.tenant_id.clone(),
            namespace: selection_request.namespace.clone(),
            request_id: selection_request.request_id.clone(),
            task_hash: selection_request.task_hash.clone(),
            selection_status: exo_dag_db_api::DagDbGraphContextSelectionStatus::Empty,
            selected_memory_refs: Vec::new(),
            selected_graph_edges: Vec::new(),
            omitted_memory_refs: Vec::new(),
            selection_trace: Vec::new(),
            selected_token_estimate: 0,
            token_budget: selection_request.token_budget,
            boundary_warnings: Vec::new(),
        },
        import_tracking_status: None,
    }
}

async fn usage_event_row_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    // PRD-D4: usage-event telemetry lives in its own structural facet
    // (node_type='usage_event'), not as a knowledge 'excerpt'.
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 AND node_type = 'usage_event'",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_one(pool)
    .await
    .expect("count usage event rows")
}

async fn knowledge_excerpt_row_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 AND node_type = 'excerpt'",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_one(pool)
    .await
    .expect("count knowledge excerpt rows")
}

async fn context_packet_row_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 AND node_type = 'context_packet'",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_one(pool)
    .await
    .expect("count context packet rows")
}

fn base_report() -> JsonValue {
    json!({
        "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
        "graph_root": "KnowledgeGraphs/dag-db",
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "actor_did": "did:exo:kg-importer",
        "batch_id": h(0x01),
        "dry_run_only": true,
        "postgres_writes": false,
        "raw_markdown_included": false,
        "proposed_memory_records": [
            memory(0x10, 0x20, "KnowledgeGraphs/dag-db/00_Index.md", "00_Index"),
            memory(0x11, 0x21, "KnowledgeGraphs/dag-db/01_Project_Brief.md", "01_Project_Brief")
        ],
        "proposed_catalog_entries": [
            catalog(0x30, 0x10, 0x20, "00_Index"),
            catalog(0x31, 0x11, 0x21, "01_Project_Brief")
        ],
        "proposed_graph_nodes": [
            graph_node(0x40, 0x10),
            graph_node(0x41, 0x11)
        ],
        "proposed_graph_edges": [
            {
                "graph_edge_id": h(0x50),
                "tenant_id": "tenant-test",
                "namespace": "dag-db",
                "graph_style": "semantic_catalog_graph",
                "from_memory_id": h(0x10),
                "to_memory_id": h(0x11),
                "edge_kind": "related_to",
                "source_edge_kind": "wikilink",
                "receipt_intent_id": h(0x91)
            }
        ],
        "proposed_required_edges": [
            {
                "required_edge_id": h(0x50),
                "tenant_id": "tenant-test",
                "namespace": "dag-db",
                "graph_style": "semantic_catalog_graph",
                "from_memory_id": h(0x10),
                "to_memory_id": h(0x11),
                "edge_kind": "related_to",
                "status": "proposed"
            }
        ],
        "proposed_placement_decisions": [
            placement(0x60, 0x10, 0xa0),
            placement(0x61, 0x11, 0xa1)
        ],
        "proposed_receipt_intents": [
            receipt(0x80, "memory", 0x10, "intake_created"),
            receipt(0x81, "memory", 0x11, "intake_created"),
            receipt(0x82, "catalog", 0x30, "memory_approved"),
            receipt(0x83, "catalog", 0x31, "memory_approved"),
            receipt(0x84, "validation_report", 0x70, "validation_created"),
            receipt(0x85, "validation_report", 0x71, "validation_created"),
            receipt(0x91, "memory", 0x50, "validation_created")
        ],
        "proposed_validation_reports": [
            validation_report(0x70, 0x10),
            validation_report(0x71, 0x11)
        ],
        "proposed_governance_reviews": [],
        "proposed_graph_view_refreshes": [],
        "proposed_route_invalidations": [],
        "proposed_subdag_boundaries": [],
        "rollback_plan": {},
        "placement_governance_summary": {},
        "review_items": [],
        "warnings": []
    })
}

fn memory(id: u8, source: u8, path: &str, title: &str) -> JsonValue {
    json!({
        "memory_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "source_path": path,
        "candidate_id": title,
        "node_type": "source",
        "source_type": "generated",
        "source_hash": h(source),
        "payload_hash": h(id + 0x20),
        "owner_did": "did:exo:kg-importer",
        "controller_did": "did:exo:kg-importer",
        "submitted_by_did": "did:exo:kg-importer",
        "consent_purpose": "retrieval",
        "title": safe(title),
        "summary": safe("summary for governed memory context"),
        "keywords": [],
        "catalog_path": ["KnowledgeGraphs", "dag-db"],
        "risk_class": "R1",
        "risk_bp": 100,
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "status": "pending",
        "receipt_intent_id": h(id + 0x70)
    })
}

fn catalog(id: u8, memory_id: u8, source: u8, title: &str) -> JsonValue {
    json!({
        "catalog_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "catalog_path": ["KnowledgeGraphs", "dag-db"],
        "catalog_level": 2,
        "title": safe(title),
        "summary": safe("catalog summary"),
        "payload_hash": h(id + 0x20),
        "source_hash": h(source),
        "status": "pending",
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "receipt_intent_id": h(id + 0x52)
    })
}

fn graph_node(id: u8, memory_id: u8) -> JsonValue {
    json!({
        "graph_node_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "node_kind": "canonical",
        "catalog_path": ["KnowledgeGraphs", "dag-db"]
    })
}

fn placement(id: u8, memory_id: u8, receipt_id: u8) -> JsonValue {
    json!({
        "placement_decision_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "input_memory_id": h(memory_id),
        "placement_trace": exo_dag_db_postgres::kg_import::required_trace(),
        "canonicalization_decision": {
            "decision_kind": "new_canonical",
            "decision_reason": "synthetic fixture",
            "confidence_bp": 0,
            "risk_class": "R1",
            "validator_status": "pending",
            "matched_memory_ids": [],
            "canonical_memory_id": null,
            "required_edges_to_create": []
        },
        "similarity_results": [],
        "validator_report": h(memory_id + 0x60),
        "receipt_intent_id": h(receipt_id)
    })
}

fn receipt(id: u8, subject_kind: &str, subject_id: u8, event_type: &str) -> JsonValue {
    json!({
        "receipt_intent_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "subject_kind": subject_kind,
        "subject_id": h(subject_id),
        "event_type": event_type,
        "actor_did": "did:exo:kg-importer",
        "reason": "synthetic fixture"
    })
}

fn validation_report(id: u8, subject_id: u8) -> JsonValue {
    json!({
        "validation_report_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "subject_kind": "memory",
        "subject_id": h(subject_id),
        "validator_did": "did:exo:kg-importer",
        "input_hash": h(id + 0x10),
        "policy_hash": h(id + 0x20),
        "validation_status": "pending",
        "risk_class": "R1",
        "risk_bp": 100,
        "decision": "allow",
        "notes": safe("synthetic validation")
    })
}

fn safe(text: &str) -> JsonValue {
    json!({
        "decision": "allow",
        "text": text,
        "redaction_codes": [],
        "original_hash": h(0xef),
        "truncated": false,
        "byte_len": text.len()
    })
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}
