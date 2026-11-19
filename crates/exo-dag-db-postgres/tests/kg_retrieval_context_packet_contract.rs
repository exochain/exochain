#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::Hash256;
use exo_dag_db_api::MemoryGraphStyle;
use exo_dag_db_postgres::{
    KG_CONTEXT_PACKET_PREVIEW_SCHEMA, KgRetrievalRequest, deterministic_layer_edge_id,
    deterministic_layer_id, deterministic_layer_membership_id,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace,
    },
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, kg_import::persist_kg_import_report,
        kg_retrieval::retrieve_kg_context_packet,
    },
};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var(KG_IMPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping kg_retrieval postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_kg_retrieval_{label}_{}", std::process::id());
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
async fn kg_retrieval_context_packet_preview_reads_persisted_rows() {
    let Some(db) = TestDb::new("preview").await else {
        return;
    };
    let report_json = base_report().to_string();
    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("persist import fixture");

    let request = base_request(500, Some(2), None);
    let first = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieve context packet preview");
    let second = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieve context packet preview again");

    assert_eq!(first, second, "retrieval preview must be deterministic");
    assert_eq!(first.schema_version, KG_CONTEXT_PACKET_PREVIEW_SCHEMA);
    assert_eq!(first.tenant_id, "tenant-test");
    assert_eq!(first.namespace, "dag-db");
    assert_eq!(first.memory_refs.len(), 2);
    assert_eq!(first.graph_edges.len(), 1);
    assert_eq!(first.selected_refs, first.memory_refs);
    assert_eq!(first.selected_graph_edges, first.graph_edges);
    assert!(first.selected_layers.is_empty());
    assert!(first.selected_layer_edges.is_empty());
    assert!(first.rollup_summaries.is_empty());
    assert!(first.flat_fallback_used);
    assert!(first.budget_report.flat_fallback_used);
    assert_eq!(first.budget_report.selected_layer_count, 0);
    assert_eq!(first.citation_handles.len(), 2);
    assert_eq!(first.citation_diagnostics.len(), 2);
    assert!(first.dry_run_or_preview_only);
    assert!(first.token_estimate <= first.token_budget);
    assert!(first.retrieval_diagnostics.preview_only);
    assert!(first.retrieval_diagnostics.deterministic_ordering);
    assert!(!first.retrieval_diagnostics.raw_markdown_returned);
    assert!(first.retrieval_diagnostics.flat_fallback_used);
    assert_eq!(first.retrieval_diagnostics.selected_memory_count, 2);
    assert_eq!(first.retrieval_diagnostics.selected_layer_count, 0);
    assert_eq!(first.retrieval_diagnostics.omitted_memory_count, 0);
    assert_eq!(first.retrieval_diagnostics.selected_graph_edge_count, 1);
    assert_eq!(first.retrieval_diagnostics.citation_handle_count, 2);
    assert!(first.retrieval_diagnostics.catalog_path_filter_applied);
    assert!(first.retrieval_diagnostics.max_memory_refs_applied);
    assert!(!first.retrieval_diagnostics.requested_memory_filter_applied);
    assert_eq!(first.validation_summary.pending_count, 2);
    assert_eq!(first.validation_summary.selected_memory_count, 2);
    assert_eq!(
        first
            .validation_summary
            .validation_status_counts
            .get("pending"),
        Some(&2)
    );
    assert_eq!(
        first.validation_summary.risk_class_counts.get("R1"),
        Some(&2)
    );
    assert_eq!(
        first
            .validation_summary
            .dag_finality_status_counts
            .get("pending"),
        Some(&2)
    );
    assert_eq!(
        first
            .validation_summary
            .council_status_counts
            .get("not_required"),
        Some(&2)
    );
    assert_eq!(first.graph_path_summary.graph_edge_count, 1);
    assert_eq!(
        first.graph_path_summary.graph_styles_seen,
        vec!["semantic_catalog_graph".to_owned()]
    );
    assert_eq!(
        first.graph_path_summary.edge_kinds_seen,
        vec!["related_to".to_owned()]
    );
    assert_eq!(first.graph_path_summary.connected_memory_count, 2);
    assert_eq!(first.graph_path_summary.isolated_memory_count, 0);
    assert_eq!(first.graph_edges[0].edge_kind, "related_to");
    assert_eq!(first.graph_edges[0].graph_style, "semantic_catalog_graph");
    assert!(
        first
            .memory_refs
            .iter()
            .all(|memory| memory.source_path.is_none())
    );
    assert!(first.memory_refs.iter().all(|memory| {
        memory.catalog_path == vec!["KnowledgeGraphs".to_owned(), "dag-db".to_owned()]
    }));
    assert!(first.memory_refs.iter().all(|memory| {
        memory.memory_status == "pending"
            && memory.council_status == "not_required"
            && memory.dag_finality_status == "pending"
            && memory
                .selection_reasons
                .contains(&"within_token_budget".to_owned())
            && memory
                .selection_reasons
                .contains(&"has_citation_handle".to_owned())
            && memory
                .selection_reasons
                .contains(&"has_graph_node".to_owned())
            && memory
                .selection_reasons
                .contains(&"has_validation_report".to_owned())
    }));
    assert!(first.citation_diagnostics.iter().all(|diagnostic| {
        diagnostic.citation_status == "available" && diagnostic.validation_report_id.is_some()
    }));
    assert!(
        first
            .warnings
            .contains(&"preview_only_not_production_route".to_owned())
    );
    assert!(
        first
            .warnings
            .contains(&"origin_path_not_persisted".to_owned())
    );

    let serialized = serde_json::to_string(&first).expect("serialize preview");
    assert!(serialized.contains("raw_markdown_returned"));
    assert!(!serialized.contains("raw_body"));
    assert!(!serialized.contains("# DAG DB Knowledge Center"));
    assert!(!serialized.contains("KnowledgeGraphs/dag-db/00_Index.md"));
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_layered_context_packet_preview_reads_layer_evidence() {
    let Some(db) = TestDb::new("layered_preview").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &layered_report().to_string())
        .await
        .expect("persist layered import fixture");

    let request = KgRetrievalRequest {
        layer_path: Some("root".into()),
        max_layer_depth: Some(1),
        max_layers_selected: Some(4),
        max_nodes_per_layer: Some(1),
        max_layer_edges: Some(4),
        ..base_request(500, Some(4), None)
    };
    let preview = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieve layered context packet preview");

    assert!(!preview.flat_fallback_used);
    assert!(!preview.budget_report.flat_fallback_used);
    assert_eq!(preview.selected_refs, preview.memory_refs);
    assert_eq!(preview.selected_graph_edges, preview.graph_edges);
    assert_eq!(preview.selected_layers.len(), 2);
    assert_eq!(preview.selected_layer_edges.len(), 1);
    assert_eq!(preview.rollup_summaries.len(), 2);
    assert_eq!(preview.budget_report.max_layer_depth, 1);
    assert_eq!(preview.budget_report.max_nodes_per_layer, 1);
    assert_eq!(preview.budget_report.selected_layer_count, 2);
    assert_eq!(preview.budget_report.selected_layer_edge_count, 1);
    assert_eq!(preview.budget_report.active_layer_edge_count, 1);
    assert_eq!(preview.budget_report.excluded_demoted_layer_edge_count, 0);
    assert_eq!(
        preview.budget_report.excluded_tombstoned_layer_edge_count,
        0
    );
    assert_eq!(preview.retrieval_diagnostics.selected_layer_count, 2);
    assert_eq!(preview.retrieval_diagnostics.selected_layer_edge_count, 1);
    assert_eq!(preview.retrieval_diagnostics.active_layer_edge_count, 1);
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_demoted_layer_edge_count,
        0
    );
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_tombstoned_layer_edge_count,
        0
    );
    assert!(preview.retrieval_diagnostics.layer_path_filter_applied);
    assert!(!preview.retrieval_diagnostics.flat_fallback_used);
    assert!(
        preview
            .warnings
            .contains(&"layer_metadata_available".to_owned())
    );

    let selected_layer_paths = preview
        .selected_layers
        .iter()
        .map(|layer| layer.layer_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(selected_layer_paths, vec!["root", "root/knowledge-graph"]);
    assert_eq!(
        preview.selected_layer_edges[0].edge_kind,
        "contains_subgraph"
    );
    assert_eq!(preview.memory_refs.len(), 2);
    assert_eq!(preview.memory_refs[0].layer_path.as_deref(), Some("root"));
    assert_eq!(
        preview.memory_refs[1].layer_path.as_deref(),
        Some("root/knowledge-graph")
    );
    assert!(preview.memory_refs.iter().all(|memory| {
        memory.layer_id.is_some()
            && memory.layer_depth.is_some()
            && memory.rollup_summary_ref.is_some()
            && memory
                .selection_reasons
                .iter()
                .any(|reason| reason == "has_layer_membership")
    }));

    let serialized = serde_json::to_string(&preview).expect("serialize layered preview");
    assert!(serialized.contains("selected_layers"));
    assert!(serialized.contains("selected_layer_edges"));
    assert!(serialized.contains("rollup_summaries"));
    assert!(!serialized.contains("raw_body"));
    assert!(!serialized.contains("KnowledgeGraphs/dag-db/00_Index.md"));
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_layer_metadata_passthrough_uses_existing_packet_fields() {
    let Some(db) = TestDb::new("layer_metadata").await else {
        return;
    };
    let report_json = layered_report().to_string();
    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("persist layered import fixture");

    let preview = retrieve_kg_context_packet(&db.pool, &base_request(500, Some(2), None))
        .await
        .expect("retrieve layered context packet preview");
    let replay = retrieve_kg_context_packet(&db.pool, &base_request(500, Some(2), None))
        .await
        .expect("retrieve layered context packet preview again");

    assert_eq!(
        preview, replay,
        "layer metadata passthrough must be deterministic"
    );
    assert_eq!(preview.schema_version, KG_CONTEXT_PACKET_PREVIEW_SCHEMA);
    assert_eq!(preview.memory_refs.len(), 2);
    assert_eq!(preview.graph_edges.len(), 1);
    assert_eq!(preview.selected_refs, preview.memory_refs);
    assert_eq!(preview.selected_graph_edges, preview.graph_edges);
    assert_eq!(preview.selected_layers.len(), 2);
    assert_eq!(preview.selected_layers[0].layer_path, "root");
    assert_eq!(preview.selected_layers[0].selected_memory_count, 1);
    assert_eq!(
        preview.selected_layers[1].layer_path,
        "root/knowledge-graph"
    );
    assert_eq!(preview.selected_layers[1].selected_memory_count, 1);
    assert_eq!(preview.selected_layer_edges.len(), 1);
    assert_eq!(
        preview.selected_layer_edges[0].from_layer_id,
        layer_id("root", 0)
    );
    assert_eq!(
        preview.selected_layer_edges[0].to_layer_id,
        layer_id("root/knowledge-graph", 1)
    );
    assert_eq!(
        preview.selected_layer_edges[0].edge_kind,
        "contains_subgraph"
    );
    assert_eq!(preview.rollup_summaries.len(), 2);
    assert_eq!(preview.budget_report.selected_layer_count, 2);
    assert_eq!(preview.budget_report.selected_layer_edge_count, 1);
    assert_eq!(preview.budget_report.active_layer_edge_count, 1);
    assert_eq!(preview.budget_report.excluded_demoted_layer_edge_count, 0);
    assert_eq!(
        preview.budget_report.excluded_tombstoned_layer_edge_count,
        0
    );
    assert_eq!(preview.budget_report.selected_memory_ref_count, 2);
    assert!(!preview.flat_fallback_used);
    assert_eq!(preview.retrieval_diagnostics.selected_layer_count, 2);
    assert_eq!(preview.retrieval_diagnostics.selected_layer_edge_count, 1);
    assert_eq!(preview.retrieval_diagnostics.active_layer_edge_count, 1);
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_demoted_layer_edge_count,
        0
    );
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_tombstoned_layer_edge_count,
        0
    );
    assert!(
        preview
            .warnings
            .contains(&"layer_metadata_available".to_owned())
    );

    let root_ref = preview
        .memory_refs
        .iter()
        .find(|memory| memory.memory_id == h(0x10))
        .expect("root layer memory selected");
    let expected_root_layer_id = layer_id("root", 0);
    assert_eq!(
        root_ref.layer_id.as_deref(),
        Some(expected_root_layer_id.as_str())
    );
    assert_eq!(root_ref.layer_path.as_deref(), Some("root"));
    assert_eq!(root_ref.layer_depth, Some(0));
    assert_eq!(root_ref.layer_kind.as_deref(), Some("root"));
    assert_eq!(root_ref.layer_membership_role.as_deref(), Some("root"));
    assert_layer_reason(root_ref, "layer_path:root");
    assert_layer_reason(root_ref, "layer_depth:0");
    assert_layer_reason(root_ref, "layer_kind:root");
    assert_layer_reason(root_ref, "membership_role:root");

    let kg_ref = preview
        .memory_refs
        .iter()
        .find(|memory| memory.memory_id == h(0x11))
        .expect("knowledge graph layer memory selected");
    let expected_kg_layer_id = layer_id("root/knowledge-graph", 1);
    assert_eq!(
        kg_ref.layer_id.as_deref(),
        Some(expected_kg_layer_id.as_str())
    );
    assert_eq!(kg_ref.layer_path.as_deref(), Some("root/knowledge-graph"));
    assert_eq!(kg_ref.layer_depth, Some(1));
    assert_eq!(kg_ref.layer_kind.as_deref(), Some("knowledge_graph"));
    assert_eq!(kg_ref.layer_membership_role.as_deref(), Some("member"));
    assert_layer_reason(kg_ref, "layer_path:root/knowledge-graph");
    assert_layer_reason(kg_ref, "layer_depth:1");
    assert_layer_reason(kg_ref, "layer_kind:knowledge_graph");
    assert_layer_reason(kg_ref, "membership_role:member");

    let serialized = serde_json::to_string(&preview).expect("serialize layered preview");
    assert!(serialized.contains("layer_path:root/knowledge-graph"));
    assert!(serialized.contains("\"selected_layers\""));
    assert!(!serialized.contains("raw_body"));
    assert!(!serialized.contains("\"raw_markdown\":"));
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_layer_hygiene_excludes_inactive_layer_edges() {
    let Some(db) = TestDb::new("layer_hygiene").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &layered_hygiene_report().to_string())
        .await
        .expect("persist layered hygiene import fixture");

    let request = KgRetrievalRequest {
        layer_path: Some("root".into()),
        max_layer_depth: Some(1),
        max_layers_selected: Some(4),
        max_nodes_per_layer: Some(2),
        max_layer_edges: Some(4),
        ..base_request(500, Some(4), None)
    };
    let preview = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieve layered hygiene context packet preview");

    assert!(!preview.flat_fallback_used);
    assert_eq!(
        preview
            .selected_layers
            .iter()
            .map(|layer| layer.layer_path.as_str())
            .collect::<Vec<_>>(),
        vec!["root", "root/knowledge-graph"]
    );
    assert_eq!(preview.selected_layer_edges.len(), 1);
    assert_eq!(
        preview.selected_layer_edges[0].layer_edge_id,
        layer_edge_id(("root", 0), ("root/knowledge-graph", 1))
    );
    assert_eq!(preview.budget_report.active_layer_edge_count, 1);
    assert_eq!(preview.budget_report.excluded_demoted_layer_edge_count, 1);
    assert_eq!(
        preview.budget_report.excluded_tombstoned_layer_edge_count,
        1
    );
    assert_eq!(preview.retrieval_diagnostics.active_layer_edge_count, 1);
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_demoted_layer_edge_count,
        1
    );
    assert_eq!(
        preview
            .retrieval_diagnostics
            .excluded_tombstoned_layer_edge_count,
        1
    );
    assert!(
        preview
            .warnings
            .contains(&"layer_hygiene_exclusions_applied".to_owned())
    );
    assert!(
        preview.selected_layers.iter().all(
            |layer| layer.layer_path != "root/demoted" && layer.layer_path != "root/tombstoned"
        )
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_layer_hygiene_rejects_unknown_state() {
    let Some(db) = TestDb::new("layer_hygiene_invalid").await else {
        return;
    };
    let mut report = layered_hygiene_report();
    report["proposed_layer_edges"][0]["metadata"] = json!({"hygiene_state": "unknown"});
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect_err("import must reject an unknown hygiene state");

    // Import can no longer persist an invalid state, so corrupt the row
    // directly to prove retrieval still fails closed on legacy rows.
    persist_kg_import_report(&db.pool, &layered_hygiene_report().to_string())
        .await
        .expect("persist layered hygiene import fixture");
    sqlx::query(
        "UPDATE dagdb_graph_layer_edges SET metadata = '{\"hygiene_state\":\"unknown\"}'::jsonb",
    )
    .execute(&db.pool)
    .await
    .expect("corrupt layer edge hygiene state");

    let error = retrieve_kg_context_packet(&db.pool, &base_request(500, Some(4), None))
        .await
        .expect_err("invalid hygiene state must fail closed");
    assert!(matches!(
        error,
        exo_dag_db_postgres::KgRetrievalError::InvalidRequest { ref reason }
            if reason == "invalid_layer_edge_hygiene_state"
    ));
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_layer_hygiene_rejects_missing_state() {
    let Some(db) = TestDb::new("layer_hygiene_missing").await else {
        return;
    };
    // Import now writes a hygiene default, so strip the state directly to
    // prove retrieval still fails closed on legacy rows without one.
    persist_kg_import_report(&db.pool, &layered_hygiene_report().to_string())
        .await
        .expect("persist layered hygiene import fixture");
    sqlx::query("UPDATE dagdb_graph_layer_edges SET metadata = metadata - 'hygiene_state'")
        .execute(&db.pool)
        .await
        .expect("strip layer edge hygiene state");

    let error = retrieve_kg_context_packet(&db.pool, &base_request(500, Some(4), None))
        .await
        .expect_err("missing hygiene state must fail closed");
    assert!(matches!(
        error,
        exo_dag_db_postgres::KgRetrievalError::InvalidRequest { ref reason }
            if reason == "missing_layer_edge_hygiene_state"
    ));
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_reads_layer_edges_imported_without_hygiene_metadata() {
    let Some(db) = TestDb::new("layer_hygiene_default").await else {
        return;
    };
    // Regression: a normal import that omits hygiene metadata must not poison
    // later layered retrieval; the persisted row defaults to active.
    let mut report = layered_report();
    report["proposed_layer_edges"][0]["metadata"] = json!({});
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("persist import fixture without hygiene metadata");

    let request = KgRetrievalRequest {
        layer_path: Some("root".into()),
        max_layer_depth: Some(1),
        max_layers_selected: Some(4),
        max_nodes_per_layer: Some(2),
        max_layer_edges: Some(4),
        ..base_request(500, Some(4), None)
    };
    let preview = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieval must read defaulted hygiene state");
    assert_eq!(preview.selected_layer_edges.len(), 1);
    assert_eq!(preview.budget_report.active_layer_edge_count, 1);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_rollup_summaries_exclude_unselected_root_memories() {
    let Some(db) = TestDb::new("rollup_minimization").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &layered_report().to_string())
        .await
        .expect("persist layered import fixture");

    // Narrow the request to a single memory: the root layer's root memory
    // h(0x10) is filtered out, so its title/summary must not leak through
    // rollup_summaries.
    let request = KgRetrievalRequest {
        layer_path: Some("root".into()),
        max_layer_depth: Some(1),
        max_layers_selected: Some(4),
        max_nodes_per_layer: Some(2),
        max_layer_edges: Some(4),
        ..base_request(500, Some(4), Some(vec![h(0x11)]))
    };
    let preview = retrieve_kg_context_packet(&db.pool, &request)
        .await
        .expect("retrieve narrowed layered preview");

    assert_eq!(preview.memory_refs.len(), 1);
    assert_eq!(preview.memory_refs[0].memory_id, h(0x11));
    assert!(
        preview
            .rollup_summaries
            .iter()
            .all(|rollup| rollup.memory_id == h(0x11)),
        "rollup summaries must not include filtered-out root memories"
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_scopes_and_budget_are_enforced() {
    let Some(db) = TestDb::new("scope_budget").await else {
        return;
    };
    let report_json = base_report().to_string();
    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("persist import fixture");

    let limited = retrieve_kg_context_packet(&db.pool, &base_request(500, Some(1), None))
        .await
        .expect("limited preview");
    assert_eq!(limited.memory_refs.len(), 1);
    assert_eq!(limited.graph_edges.len(), 0);
    assert_eq!(limited.omitted_memory_ids.len(), 1);
    assert!(limited.retrieval_diagnostics.max_memory_refs_applied);
    assert!(
        limited
            .omitted_memory_refs
            .iter()
            .any(|memory| { memory.reason == "max_memory_refs_exceeded" })
    );
    assert!(
        limited
            .warnings
            .contains(&"context_truncated_by_max_memory_refs".to_owned())
    );

    let tiny_budget = retrieve_kg_context_packet(&db.pool, &base_request(1, None, None))
        .await
        .expect("tiny-budget preview");
    assert!(tiny_budget.memory_refs.is_empty());
    assert_eq!(tiny_budget.graph_edges.len(), 0);
    assert_eq!(tiny_budget.omitted_memory_refs.len(), 2);
    assert!(
        tiny_budget
            .omitted_memory_refs
            .iter()
            .all(|memory| { memory.reason == "token_budget_exceeded" })
    );
    assert!(
        tiny_budget
            .warnings
            .contains(&"no_matching_memory".to_owned())
    );
    assert!(
        tiny_budget
            .warnings
            .contains(&"context_truncated_by_token_budget".to_owned())
    );

    let requested_subset = retrieve_kg_context_packet(
        &db.pool,
        &base_request(500, None, Some(vec![h(0x11), h(0x10)])),
    )
    .await
    .expect("requested preview");
    assert_eq!(requested_subset.memory_refs[0].memory_id, h(0x11));
    assert_eq!(requested_subset.memory_refs[1].memory_id, h(0x10));
    assert!(
        requested_subset
            .retrieval_diagnostics
            .requested_memory_filter_applied
    );
    assert!(requested_subset.memory_refs.iter().all(|memory| {
        memory
            .selection_reasons
            .contains(&"matched_requested_memory_id".to_owned())
    }));

    let requested_one =
        retrieve_kg_context_packet(&db.pool, &base_request(500, None, Some(vec![h(0x11)])))
            .await
            .expect("requested single preview");
    assert_eq!(requested_one.memory_refs.len(), 1);
    assert!(requested_one.omitted_memory_refs.iter().any(|memory| {
        memory.reason == "requested_memory_filter_mismatch" && memory.memory_id == h(0x10)
    }));

    let catalog_mismatch = retrieve_kg_context_packet(
        &db.pool,
        &KgRetrievalRequest {
            catalog_path: Some(vec!["KnowledgeGraphs".into(), "missing".into()]),
            ..base_request(500, None, None)
        },
    )
    .await
    .expect("catalog mismatch preview");
    assert!(catalog_mismatch.memory_refs.is_empty());
    assert!(
        catalog_mismatch
            .omitted_memory_refs
            .iter()
            .all(|memory| { memory.reason == "catalog_path_filter_mismatch" })
    );

    let unknown_tenant = retrieve_kg_context_packet(
        &db.pool,
        &KgRetrievalRequest {
            tenant_id: "missing-tenant".into(),
            namespace: "dag-db".into(),
            ..base_request(500, None, None)
        },
    )
    .await
    .expect("unknown tenant returns empty preview");
    assert!(unknown_tenant.memory_refs.is_empty());
    assert!(unknown_tenant.graph_edges.is_empty());
    assert!(
        unknown_tenant
            .warnings
            .contains(&"no_matching_memory".to_owned())
    );
    assert_eq!(
        unknown_tenant.retrieval_diagnostics.selected_memory_count,
        0
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_retrieval_unresolved_links_are_not_active_edges() {
    let Some(db) = TestDb::new("unresolved").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_graph_edges"] = json!([]);
    report["proposed_required_edges"] = json!([]);
    report["review_items"] = json!([
        {
            "source_path": "KnowledgeGraphs/dag-db/01_Project_Brief.md",
            "target_wikilink": "Missing Node",
            "status": "unresolved",
            "reason": "synthetic unresolved wikilink"
        }
    ]);
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("persist review-only unresolved fixture");

    let preview = retrieve_kg_context_packet(&db.pool, &base_request(500, None, None))
        .await
        .expect("retrieve unresolved preview");
    assert_eq!(preview.memory_refs.len(), 2);
    assert!(preview.graph_edges.is_empty());
    assert_eq!(preview.graph_path_summary.graph_edge_count, 0);
    assert_eq!(preview.graph_path_summary.isolated_memory_count, 2);
    assert!(
        preview
            .citation_handles
            .iter()
            .all(|citation| citation.graph_edge_ids.is_empty())
    );
    assert!(
        preview
            .citation_diagnostics
            .iter()
            .all(|diagnostic| { diagnostic.citation_status == "missing_graph_edge" })
    );
    assert!(
        preview
            .warnings
            .contains(&"unresolved_review_items_not_active_edges".to_owned())
    );
    assert!(preview.warnings.contains(&"graph_edge_missing".to_owned()));
    db.cleanup().await;
}

async fn exo_dag_table_count(pool: &PgPool) -> i64 {
    let row = sqlx::query(
        "SELECT count(*)::bigint AS table_count FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name IN ('dag_nodes', 'dag_committed')",
    )
    .fetch_one(pool)
    .await
    .expect("count exo-dag tables");
    row.try_get("table_count").expect("table count column")
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn base_request(
    token_budget: u32,
    max_memory_refs: Option<u32>,
    requested_memory_ids: Option<Vec<String>>,
) -> KgRetrievalRequest {
    KgRetrievalRequest {
        tenant_id: "tenant-test".into(),
        namespace: "dag-db".into(),
        task_hash: Some(h(0xaa)),
        task_description: None,
        token_budget,
        requested_memory_ids: requested_memory_ids.unwrap_or_default(),
        catalog_path: Some(vec!["KnowledgeGraphs".into(), "dag-db".into()]),
        max_memory_refs,
        layer_path: None,
        max_layer_depth: None,
        max_layers_selected: None,
        max_nodes_per_layer: None,
        max_layer_edges: None,
    }
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

fn layered_report() -> JsonValue {
    let root_layer_id = layer_id("root", 0);
    let kg_layer_id = layer_id("root/knowledge-graph", 1);
    let mut report = base_report();
    report["proposed_layers"] = json!([
        {
            "layer_id": &root_layer_id,
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "root_memory_id": h(0x10),
            "parent_layer_id": null,
            "parent_graph_node_id": null,
            "layer_depth": 0,
            "layer_kind": "root",
            "graph_style": "semantic_catalog_graph",
            "layer_path": "root",
            "metadata": {"source": "kg_retrieval_context_packet_contract"}
        },
        {
            "layer_id": &kg_layer_id,
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "root_memory_id": h(0x11),
            "parent_layer_id": &root_layer_id,
            "parent_graph_node_id": h(0x40),
            "layer_depth": 1,
            "layer_kind": "knowledge_graph",
            "graph_style": "semantic_catalog_graph",
            "layer_path": "root/knowledge-graph",
            "metadata": {"source": "kg_retrieval_context_packet_contract"}
        }
    ]);
    report["proposed_layer_memberships"] = json!([
        {
            "layer_membership_id": membership_id("root", 0, 0x40),
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "layer_id": &root_layer_id,
            "graph_node_id": h(0x40),
            "graph_style": "semantic_catalog_graph",
            "membership_role": "root",
            "local_node_rank": 0,
            "metadata": {}
        },
        {
            "layer_membership_id": membership_id("root/knowledge-graph", 1, 0x41),
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "layer_id": &kg_layer_id,
            "graph_node_id": h(0x41),
            "graph_style": "semantic_catalog_graph",
            "membership_role": "member",
            "local_node_rank": 0,
            "metadata": {}
        }
    ]);
    report["proposed_layer_edges"] = json!([
        {
            "layer_edge_id": layer_edge_id(("root", 0), ("root/knowledge-graph", 1)),
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "graph_style": "semantic_catalog_graph",
            "from_layer_id": &root_layer_id,
            "to_layer_id": &kg_layer_id,
            "edge_kind": "contains_subgraph",
            "receipt_hash": null,
            "metadata": {"hygiene_state": "active"}
        }
    ]);
    report["proposed_placement_decisions"][0]["target_layer_path"] = json!("root");
    report["proposed_placement_decisions"][0]["target_layer_depth"] = json!(0);
    report["proposed_placement_decisions"][0]["target_layer_reason"] = json!("fixture_root_layer");
    report["proposed_placement_decisions"][0]["created_child_layer_id"] = JsonValue::Null;
    report["proposed_placement_decisions"][0]["layer_fallback_used"] = json!(false);
    report["proposed_placement_decisions"][1]["target_layer_path"] = json!("root/knowledge-graph");
    report["proposed_placement_decisions"][1]["target_layer_depth"] = json!(1);
    report["proposed_placement_decisions"][1]["target_layer_reason"] =
        json!("fixture_knowledge_graph_layer");
    report["proposed_placement_decisions"][1]["created_child_layer_id"] = json!(kg_layer_id);
    report["proposed_placement_decisions"][1]["layer_fallback_used"] = json!(false);
    report
}

fn layered_hygiene_report() -> JsonValue {
    let root_layer_id = layer_id("root", 0);
    let mut report = layered_report();
    let mut layers = report["proposed_layers"]
        .as_array()
        .expect("layered report layers")
        .clone();
    layers.push(json!({
        "layer_id": layer_id("root/demoted", 1),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "root_memory_id": h(0x11),
        "parent_layer_id": &root_layer_id,
        "parent_graph_node_id": h(0x40),
        "layer_depth": 1,
        "layer_kind": "knowledge_graph",
        "graph_style": "semantic_catalog_graph",
        "layer_path": "root/demoted",
        "metadata": {"source": "kg_retrieval_context_packet_contract"}
    }));
    layers.push(json!({
        "layer_id": layer_id("root/tombstoned", 1),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "root_memory_id": h(0x11),
        "parent_layer_id": &root_layer_id,
        "parent_graph_node_id": h(0x40),
        "layer_depth": 1,
        "layer_kind": "knowledge_graph",
        "graph_style": "semantic_catalog_graph",
        "layer_path": "root/tombstoned",
        "metadata": {"source": "kg_retrieval_context_packet_contract"}
    }));
    report["proposed_layers"] = json!(layers);

    let mut edges = report["proposed_layer_edges"]
        .as_array()
        .expect("layered report edges")
        .clone();
    edges[0]["metadata"] = json!({"hygiene_state": "active"});
    edges.push(json!({
        "layer_edge_id": layer_edge_id(("root", 0), ("root/demoted", 1)),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "from_layer_id": &root_layer_id,
        "to_layer_id": layer_id("root/demoted", 1),
        "edge_kind": "contains_subgraph",
        "receipt_hash": null,
        "metadata": {"hygiene_state": "demoted"}
    }));
    edges.push(json!({
        "layer_edge_id": layer_edge_id(("root", 0), ("root/tombstoned", 1)),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "from_layer_id": &root_layer_id,
        "to_layer_id": layer_id("root/tombstoned", 1),
        "edge_kind": "contains_subgraph",
        "receipt_hash": null,
        "metadata": {"hygiene_state": "tombstoned"}
    }));
    report["proposed_layer_edges"] = json!(edges);
    report
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
        "summary": safe("summary"),
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
        "placement_trace": required_trace(),
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

fn assert_layer_reason(memory: &exo_dag_db_postgres::KgMemoryRef, expected: &str) {
    assert!(
        memory
            .selection_reasons
            .iter()
            .any(|reason| reason == expected),
        "missing layer reason {expected} in {:?}",
        memory.selection_reasons
    );
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hash(byte: u8) -> Hash256 {
    Hash256::from_bytes([byte; 32])
}

fn derived_layer_hash(layer_path: &str, layer_depth: u32) -> Hash256 {
    deterministic_layer_id(
        "tenant-test",
        "dag-db",
        MemoryGraphStyle::SemanticCatalogGraph,
        layer_path,
        layer_depth,
    )
    .expect("derived layer id")
}

fn layer_id(layer_path: &str, layer_depth: u32) -> String {
    derived_layer_hash(layer_path, layer_depth).to_string()
}

fn membership_id(layer_path: &str, layer_depth: u32, graph_node_byte: u8) -> String {
    deterministic_layer_membership_id(
        "tenant-test",
        "dag-db",
        derived_layer_hash(layer_path, layer_depth),
        hash(graph_node_byte),
    )
    .expect("derived membership id")
    .to_string()
}

fn layer_edge_id(from: (&str, u32), to: (&str, u32)) -> String {
    deterministic_layer_edge_id(
        "tenant-test",
        "dag-db",
        MemoryGraphStyle::SemanticCatalogGraph,
        derived_layer_hash(from.0, from.1),
        derived_layer_hash(to.0, to.1),
        "contains_subgraph",
    )
    .expect("derived layer edge id")
    .to_string()
}
