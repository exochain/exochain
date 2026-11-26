#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_dag_db_api::{MemoryCandidateKind, MemoryCandidateUse, RiskClass};
use exo_dag_db_postgres::{
    KG_PORTABLE_EXPORT_SCHEMA, KgAgentWritebackHint, KgExportError, KgExportScope,
    KgRetrievalRequest, KgWritebackExistingMemory, KgWritebackProposalRequest,
    build_writeback_dry_run_report,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace,
    },
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, kg_export, kg_import::persist_kg_import_report,
        kg_retrieval::retrieve_kg_context_packet, kg_writeback::persist_kg_writeback_report,
    },
    write_kg_export_artifacts,
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
            eprintln!("skipping kg_export postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set");
            return None;
        };
        let schema = format!("dagdb_kg_export_{label}_{}", std::process::id());
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
async fn kg_export_missing_database_url_fails_closed() {
    let result =
        kg_export::build_kg_portable_export_from_database_url(None, &export_scope(), &[]).await;
    assert!(matches!(
        result,
        Err(KgExportError::MissingDatabaseUrl { .. })
    ));
}

#[tokio::test]
async fn kg_export_reads_current_schema_rows_and_writes_deterministic_artifacts() {
    let Some(db) = TestDb::new("portable_report").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    let writeback_report = writeback_report(&preview);
    persist_kg_writeback_report(
        &db.pool,
        &serde_json::to_string(&writeback_report).expect("serialize writeback report"),
    )
    .await
    .expect("persist writeback report");

    let scope = export_scope();
    let first =
        kg_export::build_kg_portable_export(&db.pool, &scope, std::slice::from_ref(&preview))
            .await
            .expect("build export");
    let second =
        kg_export::build_kg_portable_export(&db.pool, &scope, std::slice::from_ref(&preview))
            .await
            .expect("build export again");
    assert_eq!(first, second, "portable export must be deterministic");
    assert_eq!(first.schema_version, KG_PORTABLE_EXPORT_SCHEMA);
    assert_eq!(first.tenant_id, "tenant-test");
    assert_eq!(first.namespace, "dag-db");
    assert_eq!(first.memory_records.len(), 3);
    assert_eq!(first.catalog_entries.len(), 3);
    assert_eq!(first.graph_nodes.len(), 3);
    assert_eq!(first.graph_edges.len(), 3);
    assert_eq!(first.similarity_results.len(), 1);
    assert_eq!(first.canonicalization_decisions.len(), 3);
    assert_eq!(first.placement_traces.len(), 3);
    assert_eq!(first.validation_reports.len(), 3);
    assert_eq!(first.receipts.len(), 8);
    assert_eq!(first.subject_receipt_heads.len(), 8);
    assert_eq!(first.context_packet_previews.len(), 1);
    assert_eq!(first.writeback_summaries.len(), 1);
    assert!(!first.idempotency_references.is_empty());
    assert_eq!(first.citation_index.len(), 2);
    assert!(!first.provenance_index.is_empty());
    assert_eq!(
        first
            .diagnostics
            .section_counts
            .get("memory_records")
            .copied(),
        Some(3)
    );
    assert_eq!(
        first.diagnostics.section_counts.get("graph_edges").copied(),
        Some(3)
    );
    assert_eq!(
        first.diagnostics.section_hashes,
        first.hashes.section_hashes
    );
    assert_eq!(
        first.diagnostics.citation_diagnostics.citation_handle_count,
        2
    );
    assert_eq!(
        first.diagnostics.citation_diagnostics.memory_coverage_count,
        2
    );
    assert_eq!(
        first
            .diagnostics
            .citation_diagnostics
            .receipt_coverage_count,
        2
    );
    assert!(
        first
            .diagnostics
            .citation_diagnostics
            .validation_report_coverage_count
            > 0
    );
    assert!(
        first
            .diagnostics
            .citation_diagnostics
            .graph_edge_coverage_count
            > 0
    );
    assert_eq!(
        first
            .diagnostics
            .citation_diagnostics
            .missing_coverage_count,
        0
    );
    assert_eq!(
        first
            .diagnostics
            .provenance_diagnostics
            .memory_provenance_count,
        3
    );
    assert_eq!(
        first
            .diagnostics
            .provenance_diagnostics
            .validation_provenance_count,
        3
    );
    assert_eq!(
        first
            .diagnostics
            .provenance_diagnostics
            .receipt_provenance_count,
        8
    );
    assert_eq!(
        first
            .diagnostics
            .provenance_diagnostics
            .missing_latest_receipt_count,
        0
    );
    assert!(
        first
            .diagnostics
            .provenance_diagnostics
            .preview_only_provenance_count
            > 0
    );
    assert!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .markdown_body_content_excluded
    );
    assert!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .private_payload_content_excluded
    );
    assert!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .database_connection_values_excluded
    );
    assert!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .gateway_secrets_excluded
    );
    assert!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .private_keys_excluded
    );
    assert_eq!(
        first
            .diagnostics
            .redaction_omission_diagnostics
            .source_path_omission_count,
        1
    );
    assert_eq!(
        first
            .diagnostics
            .advisory_deferred_diagnostics
            .route_invalidation_advisory_count,
        1
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred_diagnostics
            .export_persistence_deferred
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred_diagnostics
            .gateway_api_deferred
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred_diagnostics
            .route_invalidation_writes_deferred
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred_diagnostics
            .exo_dag_writes_deferred
    );
    assert!(first.diagnostics.deterministic_ordering);
    assert!(first.diagnostics.raw_material_exclusion_enforced);
    assert_eq!(first.diagnostics.preview_only_context_count, 1);
    assert!(!first.hashes.whole_export_hash.is_empty());
    assert_eq!(first.export_id, first.hashes.export_id_material_hash);
    assert!(first.verification.body_payload_exclusion_enforced);
    assert!(!first.verification.export_persistence_implemented);
    assert!(!first.verification.gateway_api_exposure_implemented);
    assert!(!first.verification.graph_explorer_changes_implemented);
    assert!(!first.verification.production_route_activation_implemented);
    assert!(!first.verification.route_invalidation_writes_implemented);
    assert!(!first.verification.exo_dag_tables_mutated);
    assert!(first.acceptance.report_only);

    let preview_record = &first.context_packet_previews[0];
    assert_eq!(
        preview_record
            .get("preview_only")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        preview_record
            .get("body_content_returned")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    let export_json = serde_json::to_string(&first).expect("serialize export");
    assert_eq!(
        export_json,
        serde_json::to_string(&second).expect("serialize export again")
    );
    assert!(!export_json.contains("raw_private_payload"));
    assert!(!export_json.contains("raw_markdown"));
    assert!(!export_json.contains("raw_model_output"));
    assert!(!export_json.contains("database_url"));
    assert!(!export_json.contains("postgres://"));
    assert!(!export_json.contains("/Users/"));
    assert!(!export_json.contains("KnowledgeGraphs/dag-db/00_Index.md"));
    assert!(export_json.contains("payload_content_not_exported"));
    assert!(export_json.contains("citation_diagnostics"));
    assert!(export_json.contains("redaction_omission_diagnostics"));

    let artifact_dir = format!("target/dagdb/kg_export/test_{}", std::process::id());
    let artifacts = write_kg_export_artifacts(
        &first,
        format!("{artifact_dir}/report.json"),
        format!("{artifact_dir}/summary.md"),
    )
    .expect("write export artifacts");
    assert!(artifacts.output_json.starts_with("target/dagdb/kg_export"));
    assert!(artifacts.output_md.starts_with("target/dagdb/kg_export"));
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    let empty_scope = KgExportScope {
        tenant_id: "missing-tenant".into(),
        namespace: "dag-db".into(),
        ..export_scope()
    };
    let empty_export = kg_export::build_kg_portable_export(&db.pool, &empty_scope, &[])
        .await
        .expect("unknown tenant export is empty and scoped");
    assert!(empty_export.memory_records.is_empty());
    assert!(empty_export.graph_edges.is_empty());
    assert!(empty_export.context_packet_previews.is_empty());
    assert_eq!(
        empty_export
            .diagnostics
            .section_counts
            .get("memory_records")
            .copied(),
        Some(0)
    );
    assert_eq!(
        empty_export
            .diagnostics
            .citation_diagnostics
            .citation_handle_count,
        0
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_export_sanitizes_persisted_validation_notes_and_context_memory_refs() {
    let Some(db) = TestDb::new("sanitize_jsonb").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let scope = export_scope();

    sqlx::query(
        "UPDATE dagdb_validation_reports \
         SET notes = notes || jsonb_build_object('source_path', '/private/leak.md', 'text_body', 'smuggled raw text')",
    )
    .execute(&db.pool)
    .await
    .expect("smuggle raw material into persisted notes");
    let smuggled_notes = kg_export::build_kg_portable_export(&db.pool, &scope, &[]).await;
    assert!(
        matches!(smuggled_notes, Err(KgExportError::ForbiddenMaterial { .. })),
        "smuggled validation notes must fail closed: {smuggled_notes:?}"
    );
    sqlx::query("UPDATE dagdb_validation_reports SET notes = notes - 'source_path' - 'text_body'")
        .execute(&db.pool)
        .await
        .expect("restore safe notes shape");

    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-test', 'dag-db', 'context_packet', $2, $3, 1, 'context_packet_created', \
                 'did:exo:fixture', 1, 0, $4, $5, 1, 0)",
    )
    .bind(vec![0xa1u8; 32])
    .bind(vec![0xaau8; 32])
    .bind(vec![0x00u8; 32])
    .bind(vec![0xa2u8; 32])
    .bind(json!({"fixture": "context_packet"}))
    .execute(&db.pool)
    .await
    .expect("insert context packet receipt fixture");
    sqlx::query(
        "INSERT INTO dagdb_route_receipts \
         (route_id, tenant_id, namespace, requesting_agent_did, task_signature_hash, approved_scope_hash, \
          candidate_memory_ids, selected_memory_ids, route_score_bp, token_budget, token_estimate, risk_bp, \
          status, validation_status, council_status, stale_at_physical_ms, stale_at_logical, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-test', 'dag-db', 'did:exo:fixture', $2, $3, '[]'::jsonb, '[]'::jsonb, \
                 9000, 4096, 256, 0, 'active', 'passed', 'not_required', 90000, 0, $4, 1, 0)",
    )
    .bind(vec![0xa3u8; 32])
    .bind(vec![0xa4u8; 32])
    .bind(vec![0xa5u8; 32])
    .bind(vec![0xa1u8; 32])
    .execute(&db.pool)
    .await
    .expect("insert route receipt fixture");
    sqlx::query(
        "INSERT INTO dagdb_context_packets \
         (context_packet_id, tenant_id, namespace, request_id, route_id, task_hash, requesting_agent_did, \
          memory_refs, packet_hash, token_budget, token_estimate, validation_status, council_status, \
          latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-test', 'dag-db', 'request-sanitize', $2, $3, 'did:exo:fixture', \
                 $4, $5, 4096, 256, 'passed', 'not_required', $6, 1, 0)",
    )
    .bind(vec![0xaau8; 32])
    .bind(vec![0xa3u8; 32])
    .bind(vec![0xa6u8; 32])
    .bind(json!([{
        "memory_id": h(0xab),
        "latest_receipt_hash": h(0xa1),
        "source_path": "/private/leak.md",
        "text_body": "smuggled raw text"
    }]))
    .bind(vec![0xa7u8; 32])
    .bind(vec![0xa1u8; 32])
    .execute(&db.pool)
    .await
    .expect("insert context packet with smuggled memory_refs");

    let export = kg_export::build_kg_portable_export(&db.pool, &scope, &[])
        .await
        .expect("export reconstructs memory_refs as ids/hashes only");
    assert_eq!(export.context_packet_records.len(), 1);
    assert_eq!(
        export.context_packet_records[0].get("memory_refs"),
        Some(&json!([{
            "memory_id": h(0xab),
            "latest_receipt_hash": h(0xa1)
        }]))
    );
    let export_json = serde_json::to_string(&export).expect("serialize export");
    assert!(!export_json.contains("leak.md"));
    assert!(!export_json.contains("smuggled raw text"));
    db.cleanup().await;
}

#[tokio::test]
async fn kg_export_rejects_cross_scope_preview_material() {
    let Some(db) = TestDb::new("cross_scope_preview").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let mut preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    preview.tenant_id = "other-tenant".into();

    let result = kg_export::build_kg_portable_export(&db.pool, &export_scope(), &[preview]).await;
    assert!(matches!(result, Err(KgExportError::InvalidScope { .. })));
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
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

fn export_scope() -> KgExportScope {
    KgExportScope {
        tenant_id: "tenant-test".into(),
        namespace: "dag-db".into(),
        included_memory_ids: Vec::new(),
        included_graph_styles: Vec::new(),
        included_writeback_idempotency_keys: Vec::new(),
        source_commit_or_repo_ref: Some("test-ref".into()),
        include_preview_context: true,
    }
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
) -> exo_dag_db_postgres::KgWritebackDryRunReport {
    let citation = preview
        .citation_handles
        .first()
        .expect("fixture citation")
        .clone();
    build_writeback_dry_run_report(KgWritebackProposalRequest {
        tenant_id: "tenant-test".into(),
        namespace: "dag-db".into(),
        requesting_agent_did: "did:exo:kg-writeback-agent".into(),
        context_packet: preview.clone(),
        hint: KgAgentWritebackHint {
            source_request_id: "source-request-export".into(),
            parent_context_packet_id: preview.context_packet_id.clone(),
            route_hint_id: preview.route_hint_id.clone(),
            task_hash: h(0xaa),
            answer_hash: Some(h(0x30)),
            output_hash: None,
            candidate_kind: MemoryCandidateKind::Summary,
            summary: "mission graph catalog".into(),
            citation_handles: vec![citation.handle.clone()],
            evidence_receipts: vec![citation.latest_receipt_hash.clone()],
            risk_hint: RiskClass::R1,
            allowed_future_uses: vec![MemoryCandidateUse::Routing, MemoryCandidateUse::Audit],
            reason_to_remember: "repository-level export fixture".into(),
            keyword_texts: Vec::new(),
            contradiction_refs: Vec::new(),
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
