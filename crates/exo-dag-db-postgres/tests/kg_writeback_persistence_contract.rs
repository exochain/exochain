#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_dag_db_api::{MemoryCandidateKind, MemoryCandidateUse, RiskClass};
use exo_dag_db_postgres::{
    KG_CONTEXT_PACKET_PREVIEW_SCHEMA, KG_WRITEBACK_PERSISTED_SUMMARY_SCHEMA, KgAgentWritebackHint,
    KgRetrievalRequest, KgWritebackExistingMemory, KgWritebackLayeredWriteback,
    KgWritebackProposalRequest, build_writeback_dry_run_report,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace,
    },
    parse_agent_writeback_hint_json,
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        kg_import::persist_kg_import_report,
        kg_retrieval::retrieve_kg_context_packet,
        kg_writeback::{
            KgWritebackPersistenceError, persist_kg_writeback_report,
            persist_kg_writeback_report_from_database_url,
        },
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
                "skipping kg_writeback postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_kg_writeback_{label}_{}", std::process::id());
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
async fn kg_writeback_from_missing_database_url_fails_closed() {
    let result = persist_kg_writeback_report_from_database_url(None, "{}").await;
    assert!(matches!(
        result,
        Err(KgWritebackPersistenceError::MissingDatabaseUrl { .. })
    ));
}

#[test]
fn kg_writeback_hint_rejects_raw_payload_and_graph_allocation_fields() {
    let raw_payload = json!({
        "source_request_id": "request-1",
        "parent_context_packet_id": h(0x30),
        "route_hint_id": h(0x31),
        "task_hash": h(0xaa),
        "output_hash": h(0xbb),
        "candidate_kind": "summary",
        "summary": "compact",
        "citation_handles": ["dagdb://kg/tenant-test/dag-db/handle"],
        "evidence_receipts": [],
        "risk_hint": "R1",
        "allowed_future_uses": ["routing"],
        "reason_to_remember": "compact",
        "raw_private_payload": "forbidden"
    });
    assert!(parse_agent_writeback_hint_json(&raw_payload.to_string()).is_err());

    let graph_allocation = json!({
        "source_request_id": "request-1",
        "parent_context_packet_id": h(0x30),
        "route_hint_id": h(0x31),
        "task_hash": h(0xaa),
        "output_hash": h(0xbb),
        "candidate_kind": "summary",
        "summary": "compact",
        "citation_handles": ["dagdb://kg/tenant-test/dag-db/handle"],
        "evidence_receipts": [],
        "risk_hint": "R1",
        "allowed_future_uses": ["routing"],
        "reason_to_remember": "compact",
        "canonical_memory_id": h(0x10)
    });
    assert!(parse_agent_writeback_hint_json(&graph_allocation.to_string()).is_err());
}

#[tokio::test]
async fn kg_writeback_persists_supported_sections_and_replays_idempotently() {
    let Some(db) = TestDb::new("supported_sections").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    assert_eq!(preview.schema_version, KG_CONTEXT_PACKET_PREVIEW_SCHEMA);

    let report = writeback_report(
        &preview,
        "source-request-duplicate",
        h(0x30),
        "summary",
        RiskClass::R1,
        false,
    );
    let report_json = serde_json::to_string(&report).expect("serialize writeback report");
    let first = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("persist writeback report");
    assert_eq!(first.schema_version, KG_WRITEBACK_PERSISTED_SUMMARY_SCHEMA);
    assert!(!first.replayed);
    assert!(first.preview_evidence_only);
    assert_eq!(first.inserted_memory_count, 1);
    assert_eq!(first.inserted_catalog_count, 1);
    assert_eq!(first.inserted_graph_node_count, 1);
    assert_eq!(first.inserted_graph_edge_count, 2);
    assert_eq!(first.inserted_layer_count, 0);
    assert_eq!(first.inserted_layer_membership_count, 0);
    assert_eq!(first.inserted_layer_edge_count, 0);
    assert_eq!(first.inserted_memory_edge_count, 1);
    assert_eq!(first.inserted_similarity_result_count, 1);
    assert_eq!(first.inserted_validation_report_count, 1);
    assert_eq!(first.inserted_placement_decision_count, 1);
    assert_eq!(first.inserted_placement_trace_count, 1);
    assert_eq!(first.inserted_receipt_count, 2);
    assert_eq!(first.inserted_subject_receipt_head_count, 2);
    assert_eq!(first.inserted_idempotency_response_count, 1);
    assert_eq!(first.persisted_route_invalidation_count, 0);
    assert_eq!(first.persisted_export_record_count, 0);
    assert_eq!(first.diagnostics.persisted_row_counts.memory_rows, 1);
    assert_eq!(first.diagnostics.persisted_row_counts.catalog_rows, 1);
    assert_eq!(first.diagnostics.persisted_row_counts.graph_node_rows, 1);
    assert_eq!(first.diagnostics.persisted_row_counts.graph_edge_rows, 2);
    assert_eq!(first.diagnostics.persisted_row_counts.layer_rows, 0);
    assert_eq!(
        first.diagnostics.persisted_row_counts.layer_membership_rows,
        0
    );
    assert_eq!(first.diagnostics.persisted_row_counts.layer_edge_rows, 0);
    assert_eq!(first.diagnostics.persisted_row_counts.memory_edge_rows, 1);
    assert_eq!(
        first
            .diagnostics
            .persisted_row_counts
            .similarity_result_rows,
        1
    );
    assert_eq!(
        first
            .diagnostics
            .persisted_row_counts
            .canonicalization_decision_rows,
        1
    );
    assert_eq!(
        first.diagnostics.persisted_row_counts.placement_trace_rows,
        1
    );
    assert_eq!(
        first
            .diagnostics
            .persisted_row_counts
            .validation_report_rows,
        1
    );
    assert_eq!(first.diagnostics.persisted_row_counts.receipt_rows, 2);
    assert_eq!(
        first
            .diagnostics
            .persisted_row_counts
            .subject_receipt_head_rows,
        2
    );
    assert_eq!(
        first
            .diagnostics
            .persisted_row_counts
            .idempotency_response_rows,
        1
    );
    assert_eq!(
        first.diagnostics.evidence.parent_context_packet_id,
        preview.context_packet_id
    );
    assert_eq!(
        first.diagnostics.evidence.route_hint_id,
        preview.route_hint_id
    );
    assert_eq!(first.diagnostics.evidence.evidence_status, "preview_only");
    assert!(first.diagnostics.evidence.tenant_namespace_match);
    assert!(
        first
            .diagnostics
            .evidence
            .evidence_warnings
            .contains(&"preview_only_context_evidence".to_owned())
    );
    assert_eq!(
        first
            .diagnostics
            .placement_governance
            .placement_decision_kind,
        "exact_duplicate"
    );
    assert_eq!(
        first.diagnostics.placement_governance.placement_status,
        "persisted_review_rows"
    );
    assert_eq!(
        first.diagnostics.layered_writeback.layered_writeback_status,
        "flat_only_no_layer_evidence"
    );
    assert_eq!(
        first
            .diagnostics
            .placement_governance
            .required_edges_to_create_count,
        1
    );
    assert_eq!(
        first.diagnostics.validation_risk_council.validation_status,
        "passed"
    );
    assert_eq!(first.diagnostics.validation_risk_council.risk_class, "R1");
    assert!(!first.diagnostics.validation_risk_council.council_required);
    assert_eq!(
        first.diagnostics.idempotency_replay.idempotency_key,
        first.idempotency_key
    );
    assert!(!first.diagnostics.idempotency_replay.replayed);
    assert!(
        first
            .diagnostics
            .idempotency_replay
            .duplicate_writeback_detected
    );
    assert_eq!(
        first.diagnostics.idempotency_replay.replay_reason,
        "new_persisted_response"
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .contains(&"route_invalidation_deferred".to_owned())
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .contains(&"export_persistence_deferred".to_owned())
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .contains(&"no_exo_dag_write".to_owned())
    );
    let first_json = serde_json::to_string(&first).expect("serialize first summary");
    assert_eq!(
        first_json,
        serde_json::to_string(&first).expect("serialize first summary again")
    );
    assert!(!first_json.contains("raw_private_payload"));
    assert!(!first_json.contains("raw_markdown"));

    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_graph_nodes").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 0);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        0
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_memory_edges").await, 1);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_similarity_results").await,
        1
    );
    assert_eq!(row_count(&db.pool, "dagdb_validation_reports").await, 3);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_canonicalization_decisions").await,
        3
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_placement_traces").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 8);
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_memory_objects", "node_type = 'answer'").await,
        1
    );
    assert_eq!(
        scalar_count_where(
            &db.pool,
            "dagdb_memory_objects",
            "consent_purpose = 'writeback'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_graph_edges", "edge_kind = 'duplicate_of'").await,
        1
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_graph_edges", "edge_kind = 'derived_from'").await,
        1
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_memory_edges", "edge_type = 'derived_from'").await,
        1
    );
    assert_eq!(
        scalar_count_where(
            &db.pool,
            "dagdb_graph_canonicalization_decisions",
            "decision_kind = 'exact_duplicate'"
        )
        .await,
        1
    );
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    assert_eq!(forbidden_raw_payload_count(&db.pool).await, 0);

    let second = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("idempotent writeback replay");
    assert!(second.replayed);
    assert!(second.diagnostics.idempotency_replay.replayed);
    assert_eq!(
        second.diagnostics.idempotency_replay.replay_reason,
        "idempotency_key_match"
    );
    let mut normalized_second = second.clone();
    normalized_second.replayed = false;
    normalized_second.diagnostics.idempotency_replay.replayed = false;
    normalized_second
        .diagnostics
        .idempotency_replay
        .replay_reason = "new_persisted_response".to_owned();
    assert_eq!(normalized_second, first);
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 3);
    assert_eq!(row_count(&db.pool, "dagdb_memory_edges").await, 1);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 8);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_writeback_persists_layered_child_rows_and_replays_idempotently() {
    let Some(db) = TestDb::new("layered_child").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    seed_canonical_parent_layer(&db.pool).await;
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");

    let mut report = writeback_report(
        &preview,
        "source-request-layered-child",
        h(0x32),
        "layered summary",
        RiskClass::R1,
        false,
    );
    report.layered_writeback = Some(layered_writeback_fixture());
    let report_json = serde_json::to_string(&report).expect("serialize layered writeback report");

    let first = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("persist layered writeback report");
    assert!(!first.replayed);
    assert_eq!(first.inserted_layer_count, 1);
    assert_eq!(first.inserted_layer_membership_count, 1);
    assert_eq!(first.inserted_layer_edge_count, 1);
    assert_eq!(first.diagnostics.persisted_row_counts.layer_rows, 1);
    assert_eq!(
        first.diagnostics.persisted_row_counts.layer_membership_rows,
        1
    );
    assert_eq!(first.diagnostics.persisted_row_counts.layer_edge_rows, 1);
    assert_eq!(
        first.diagnostics.layered_writeback.layered_writeback_status,
        "persisted_layer_rows"
    );
    assert_eq!(
        first
            .diagnostics
            .layered_writeback
            .target_layer_path
            .as_deref(),
        Some("root/canonical-writeback/source-request-layered-child")
    );
    assert_eq!(
        first
            .diagnostics
            .layered_writeback
            .parent_layer_id
            .as_deref(),
        Some(h(0xc0).as_str())
    );
    assert_eq!(
        first
            .diagnostics
            .layered_writeback
            .parent_graph_node_id
            .as_deref(),
        Some(h(0xc1).as_str())
    );
    assert!(first.diagnostics.layered_writeback.receipt_hash.is_some());
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 2);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 1);
    // Writeback-persisted layer edges must carry a hygiene state so layered
    // retrieval cannot be poisoned by rows missing one.
    let hygiene_state: String = sqlx::query_scalar(
        "SELECT metadata->>'hygiene_state' FROM dagdb_graph_layer_edges LIMIT 1",
    )
    .fetch_one(&db.pool)
    .await
    .expect("read layer edge hygiene state");
    assert_eq!(hygiene_state, "active");

    let second = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("idempotent layered writeback replay");
    assert!(second.replayed);
    let mut normalized_second = second.clone();
    normalized_second.replayed = false;
    normalized_second.diagnostics.idempotency_replay.replayed = false;
    normalized_second
        .diagnostics
        .idempotency_replay
        .replay_reason = "new_persisted_response".to_owned();
    assert_eq!(normalized_second, first);
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 2);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 1);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_writeback_rejects_layered_child_without_parent_binding() {
    let Some(db) = TestDb::new("layered_missing_parent").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");

    let mut report = writeback_report(
        &preview,
        "source-request-layered-missing-parent",
        h(0x33),
        "layered summary",
        RiskClass::R1,
        false,
    );
    report.layered_writeback = Some(layered_writeback_fixture());
    let result = persist_kg_writeback_report(
        &db.pool,
        &serde_json::to_string(&report).expect("serialize report"),
    )
    .await;

    assert!(matches!(
        result,
        Err(KgWritebackPersistenceError::Conflict { .. })
    ));
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 0);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        0
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_writeback_accepts_legacy_graph_edge_id_for_existing_natural_key() {
    let Some(db) = TestDb::new("legacy_graph_edge_id").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    let report = writeback_report(
        &preview,
        "source-request-duplicate",
        h(0x30),
        "summary",
        RiskClass::R1,
        false,
    );
    let report_json = serde_json::to_string(&report).expect("serialize writeback report");
    let first = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("persist writeback report");
    let first_graph_edge_count = row_count(&db.pool, "dagdb_graph_edges").await;
    assert!(first_graph_edge_count >= 1);

    let legacy_edge_id = h(0xfd);
    let updated = sqlx::query(
        "UPDATE dagdb_graph_edges \
         SET graph_edge_id = decode($1, 'hex') \
         WHERE tenant_id = 'tenant-test' AND namespace = 'dag-db' AND edge_kind = 'duplicate_of'",
    )
    .bind(&legacy_edge_id)
    .execute(&db.pool)
    .await
    .expect("rewrite graph edge id to legacy value");
    assert_eq!(updated.rows_affected(), 1);
    sqlx::query(
        "DELETE FROM dagdb_idempotency_keys \
         WHERE tenant_id = 'tenant-test' AND namespace = 'dag-db' AND idempotency_key = $1",
    )
    .bind(&first.idempotency_key)
    .execute(&db.pool)
    .await
    .expect("remove idempotency row to force natural-key replay path");

    let second = persist_kg_writeback_report(&db.pool, &report_json)
        .await
        .expect("legacy natural-key graph edge should not block writeback");
    assert!(!second.replayed);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_edges").await,
        first_graph_edge_count
    );
    assert_eq!(
        scalar_count_where(
            &db.pool,
            "dagdb_graph_edges",
            &format!("encode(graph_edge_id, 'hex') = '{legacy_edge_id}'")
        )
        .await,
        1
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_writeback_invalid_evidence_rolls_back_all_writeback_rows() {
    let Some(db) = TestDb::new("invalid_evidence").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    let report = writeback_report(
        &preview,
        "source-request-invalid-evidence",
        h(0xbb),
        "summary",
        RiskClass::R1,
        false,
    );
    let mut report_json = serde_json::to_value(&report).expect("report value");
    report_json["evidence_binding"]["selected_memory_ids"] = json!([h(0xff)]);

    let result = persist_kg_writeback_report(&db.pool, &report_json.to_string()).await;
    assert!(matches!(
        result,
        Err(KgWritebackPersistenceError::Conflict { .. })
            | Err(KgWritebackPersistenceError::Report(_))
    ));
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 1);
    assert_eq!(row_count(&db.pool, "dagdb_memory_edges").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 6);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_writeback_contradiction_is_review_compatible_without_route_mutation() {
    let Some(db) = TestDb::new("contradiction").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    let report = writeback_report(
        &preview,
        "source-request-contradiction",
        h(0xbc),
        "mission graph import",
        RiskClass::R3,
        true,
    );
    assert!(report.validation_proposal.needs_review);
    let summary = persist_kg_writeback_report(
        &db.pool,
        &serde_json::to_string(&report).expect("serialize report"),
    )
    .await
    .expect("persist contradiction writeback");

    assert_eq!(summary.inserted_graph_edge_count, 2);
    assert_eq!(summary.inserted_memory_edge_count, 1);
    assert!(summary.skipped_advisory_section_count >= 2);
    assert_eq!(summary.persisted_route_invalidation_count, 0);
    assert_eq!(
        summary
            .diagnostics
            .placement_governance
            .placement_decision_kind,
        "contradiction"
    );
    assert_eq!(
        summary
            .diagnostics
            .placement_governance
            .route_invalidation_status,
        "advisory"
    );
    assert!(summary.diagnostics.placement_governance.needs_review);
    assert!(
        summary
            .diagnostics
            .placement_governance
            .review_reasons
            .contains(&"contradiction_refs_require_review".to_owned())
    );
    assert_eq!(
        summary
            .diagnostics
            .validation_risk_council
            .validation_status,
        "needs_council"
    );
    assert_eq!(summary.diagnostics.validation_risk_council.risk_class, "R3");
    assert!(summary.diagnostics.validation_risk_council.council_required);
    assert_eq!(
        summary
            .diagnostics
            .advisory_deferred
            .route_invalidation_proposals,
        1
    );
    assert_eq!(
        summary
            .diagnostics
            .advisory_deferred
            .governance_review_items,
        1
    );
    assert!(
        summary
            .diagnostics
            .warning_summaries
            .contains(&"governance_review_queue_missing".to_owned())
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_graph_edges", "edge_kind = 'contradicts'").await,
        1
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_graph_edges", "edge_kind = 'derived_from'").await,
        1
    );
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_memory_edges", "edge_type = 'derived_from'").await,
        1
    );
    assert_eq!(
        scalar_count_where(
            &db.pool,
            "dagdb_validation_reports",
            "validation_status = 'needs_council'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_count_where(
            &db.pool,
            "dagdb_memory_objects",
            "council_status = 'required'"
        )
        .await,
        1
    );
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_route_invalidations").await,
        0
    );
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    db.cleanup().await;
}

async fn row_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .expect("count table rows")
}

async fn scalar_count_where(pool: &PgPool, table: &str, clause: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE {clause}"
    )))
    .fetch_one(pool)
    .await
    .expect("count filtered table rows")
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

async fn seed_canonical_parent_layer(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO dagdb_graph_nodes \
         (graph_node_id, tenant_id, namespace, memory_id, graph_style, node_kind, \
          canonical_memory_id, catalog_path, metadata, created_at_physical_ms, created_at_logical) \
         VALUES (decode($1, 'hex'), 'tenant-test', 'dag-db', decode($2, 'hex'), \
                 'canonical_memory_graph', 'canonical', decode($2, 'hex'), \
                 'KnowledgeGraphs/dag-db', '{}'::jsonb, 1, 0)",
    )
    .bind(h(0xc1))
    .bind(h(0x10))
    .execute(pool)
    .await
    .expect("seed parent canonical graph node");
    sqlx::query(
        "INSERT INTO dagdb_graph_layers \
         (layer_id, tenant_id, namespace, root_memory_id, parent_layer_id, parent_graph_node_id, \
          layer_depth, layer_kind, graph_style, layer_path, metadata, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES (decode($1, 'hex'), 'tenant-test', 'dag-db', decode($2, 'hex'), NULL, NULL, \
                 0, 'root', 'canonical_memory_graph', 'root/canonical-writeback', '{}'::jsonb, \
                 1, 0, 1, 0)",
    )
    .bind(h(0xc0))
    .bind(h(0x10))
    .execute(pool)
    .await
    .expect("seed parent layer");
    sqlx::query(
        "INSERT INTO dagdb_graph_layer_memberships \
         (layer_membership_id, tenant_id, namespace, layer_id, graph_node_id, graph_style, \
          membership_role, local_node_rank, metadata, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES (decode($1, 'hex'), 'tenant-test', 'dag-db', decode($2, 'hex'), decode($3, 'hex'), \
                 'canonical_memory_graph', 'root', 0, '{}'::jsonb, 1, 0, 1, 0)",
    )
    .bind(h(0xc2))
    .bind(h(0xc0))
    .bind(h(0xc1))
    .execute(pool)
    .await
    .expect("seed parent layer membership");
}

async fn forbidden_raw_payload_count(pool: &PgPool) -> i64 {
    let row = sqlx::query(
        "SELECT \
         (SELECT count(*) FROM dagdb_receipts \
          WHERE receipt_body::text LIKE '%raw_private_payload%' OR receipt_body::text LIKE '%raw_markdown%') + \
         (SELECT count(*) FROM dagdb_memory_objects \
          WHERE title::text LIKE '%raw_private_payload%' OR summary::text LIKE '%raw_private_payload%' \
             OR title::text LIKE '%raw_markdown%' OR summary::text LIKE '%raw_markdown%') \
         AS forbidden_count",
    )
    .fetch_one(pool)
    .await
    .expect("count forbidden raw payload markers");
    row.try_get("forbidden_count")
        .expect("forbidden count column")
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn base_request() -> KgRetrievalRequest {
    KgRetrievalRequest {
        tenant_id: "tenant-test".into(),
        namespace: "dag-db".into(),
        task_hash: Some(h(0xaa)),
        task_description: None,
        token_budget: 500,
        requested_memory_ids: Vec::new(),
        catalog_path: Some(vec!["KnowledgeGraphs".into(), "dag-db".into()]),
        max_memory_refs: Some(2),
        layer_path: None,
        max_layer_depth: None,
        max_layers_selected: None,
        max_nodes_per_layer: None,
        max_layer_edges: None,
    }
}

fn writeback_report(
    preview: &exo_dag_db_postgres::KgContextPacketPreview,
    source_request_id: &str,
    output_hash: String,
    summary: &str,
    risk_hint: RiskClass,
    contradiction: bool,
) -> exo_dag_db_postgres::KgWritebackDryRunReport {
    let citation = preview
        .citation_handles
        .first()
        .expect("fixture citation")
        .clone();
    let mut contradiction_refs = Vec::new();
    if contradiction {
        contradiction_refs.push(citation.memory_id.clone());
    }
    build_writeback_dry_run_report(KgWritebackProposalRequest {
        tenant_id: "tenant-test".into(),
        namespace: "dag-db".into(),
        requesting_agent_did: "did:exo:kg-writeback-agent".into(),
        context_packet: preview.clone(),
        hint: KgAgentWritebackHint {
            source_request_id: source_request_id.to_owned(),
            parent_context_packet_id: preview.context_packet_id.clone(),
            route_hint_id: preview.route_hint_id.clone(),
            task_hash: h(0xaa),
            answer_hash: Some(output_hash),
            output_hash: None,
            candidate_kind: MemoryCandidateKind::Summary,
            summary: summary.to_owned(),
            citation_handles: vec![citation.handle.clone()],
            evidence_receipts: vec![citation.latest_receipt_hash.clone()],
            risk_hint,
            allowed_future_uses: vec![MemoryCandidateUse::Routing, MemoryCandidateUse::Audit],
            reason_to_remember: "repository-level persisted writeback fixture".into(),
            keyword_texts: Vec::new(),
            contradiction_refs,
            supersession_refs: Vec::new(),
        },
        existing_memory: vec![KgWritebackExistingMemory {
            memory_id: h(0x10),
            payload_hash: h(0x30),
            summary: "mission graph catalog".into(),
        }],
    })
    .expect("build writeback dry-run report")
}

fn layered_writeback_fixture() -> KgWritebackLayeredWriteback {
    KgWritebackLayeredWriteback {
        target_layer_id: h(0xd0),
        target_layer_path: "root/canonical-writeback/source-request-layered-child".to_owned(),
        target_layer_depth: 1,
        target_layer_kind: "task_subgraph".to_owned(),
        target_graph_style: "canonical_memory_graph".to_owned(),
        target_layer_reason: "parent_child_source_parent_path_child".to_owned(),
        parent_layer_id: Some(h(0xc0)),
        parent_graph_node_id: Some(h(0xc1)),
        created_child_layer_id: Some(h(0xd0)),
        layer_membership_id: h(0xd1),
        membership_role: "member".to_owned(),
        local_node_rank: 0,
        layer_edge_id: Some(h(0xd2)),
        layer_edge_kind: Some("contains_subgraph".to_owned()),
        layer_fallback_used: false,
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

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}
