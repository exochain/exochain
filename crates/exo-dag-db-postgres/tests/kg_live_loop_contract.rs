#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use exo_dag_db_api::{MemoryCandidateKind, MemoryCandidateUse, RiskClass};
use exo_dag_db_postgres::{
    KG_CONTEXT_PACKET_PREVIEW_SCHEMA, KG_EXPORT_DATABASE_URL_ENV,
    KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA, KG_PORTABLE_EXPORT_SCHEMA, KgAgentWritebackHint,
    KgContextPacketPreview, KgExportError, KgExportFinalityOutboxRequest, KgExportPersistedSummary,
    KgExportScope, KgPortableExport, KgRetrievalRequest, KgWritebackExistingMemory,
    KgWritebackProposalRequest, build_writeback_dry_run_report,
    kg_import::{KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DRY_RUN_REPORT_SCHEMA, required_trace},
    postgres::{
        DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL, DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_SCHEMA_SQL, kg_export, kg_import::persist_kg_import_report,
        kg_retrieval::retrieve_kg_context_packet, kg_writeback::persist_kg_writeback_report,
    },
};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var(KG_EXPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping kg_live_loop postgres test: {KG_EXPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_kg_live_loop_{label}_{}", std::process::id());
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
        sqlx::raw_sql(DAGDB_EXPORT_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB export schema");
        sqlx::raw_sql(DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB export finality/outbox schema");
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
async fn kg_live_loop_proves_repository_path_without_production_finality() {
    let Some(db) = TestDb::new("full_loop").await else {
        return;
    };

    let import_summary = persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    assert_eq!(import_summary.inserted_memory_count, 2);
    assert_eq!(table_count(&db.pool, "dagdb_memory_objects").await, 2);

    let preview = retrieve_kg_context_packet(&db.pool, &base_request())
        .await
        .expect("retrieve context preview");
    assert_eq!(preview.schema_version, KG_CONTEXT_PACKET_PREVIEW_SCHEMA);
    assert_eq!(preview.memory_refs.len(), 2);
    assert!(preview.dry_run_or_preview_only);
    assert!(
        preview
            .warnings
            .contains(&"preview_only_not_production_route".to_owned())
    );

    let writeback_report = writeback_report(&preview);
    let writeback_summary = persist_kg_writeback_report(
        &db.pool,
        &serde_json::to_string(&writeback_report).expect("serialize writeback report"),
    )
    .await
    .expect("persist writeback report");
    assert_eq!(writeback_summary.inserted_memory_count, 1);
    assert_eq!(writeback_summary.inserted_graph_edge_count, 2);
    assert_eq!(writeback_summary.inserted_memory_edge_count, 1);
    assert_eq!(writeback_summary.persisted_route_invalidation_count, 0);
    assert_eq!(table_count(&db.pool, "dagdb_memory_objects").await, 3);
    assert_eq!(table_count(&db.pool, "dagdb_graph_edges").await, 3);
    assert_eq!(table_count(&db.pool, "dagdb_memory_edges").await, 1);

    let export = kg_export::build_kg_portable_export(
        &db.pool,
        &export_scope(),
        std::slice::from_ref(&preview),
    )
    .await
    .expect("build portable export");
    let export_again = kg_export::build_kg_portable_export(
        &db.pool,
        &export_scope(),
        std::slice::from_ref(&preview),
    )
    .await
    .expect("build portable export again");
    assert_eq!(export, export_again);
    assert_eq!(export.schema_version, KG_PORTABLE_EXPORT_SCHEMA);
    assert_eq!(export.memory_records.len(), 3);
    assert_eq!(export.graph_edges.len(), 3);
    assert_eq!(export.writeback_summaries.len(), 1);
    assert_eq!(export.context_packet_previews.len(), 1);
    assert!(export.diagnostics.raw_material_exclusion_enforced);
    assert!(!export.verification.production_route_activation_implemented);
    assert!(!export.verification.route_invalidation_writes_implemented);
    assert!(!export.verification.exo_dag_tables_mutated);
    assert_no_forbidden_material(
        "portable export",
        &serde_json::to_string(&export).expect("serialize portable export"),
    );

    let persisted_export =
        kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
            .await
            .expect("persist portable export");
    assert_eq!(persisted_export.export_id, export.export_id);
    assert_eq!(persisted_export.inserted_export_count, 1);
    assert_eq!(persisted_export.inserted_challenge_count, 5);
    assert_eq!(persisted_export.inserted_receipt_count, 1);
    assert_eq!(persisted_export.inserted_subject_receipt_head_count, 1);
    assert_eq!(persisted_export.persisted_route_invalidation_count, 0);
    assert_eq!(persisted_export.persisted_dag_outbox_count, 0);
    assert_eq!(persisted_export.persisted_raw_artifact_count, 0);
    assert_eq!(persisted_export.persisted_exo_dag_write_count, 0);
    assert_no_forbidden_material(
        "persisted export summary",
        &serde_json::to_string(&persisted_export).expect("serialize persisted export summary"),
    );

    let verification = kg_export::verify_persisted_kg_export(
        &db.pool,
        &export,
        &persisted_export,
        "did:exo:exporter",
    )
    .await
    .expect("verify persisted export rows");
    assert!(verification.verified);
    assert_eq!(verification.dagdb_dag_outbox_rows, 0);
    assert_eq!(verification.route_invalidation_rows, 0);
    assert_eq!(verification.exo_dag_rows, 0);

    let finality_request = KgExportFinalityOutboxRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        export_id: export.export_id.clone(),
        requester_did: "did:exo:finality-operator".to_owned(),
        idempotency_key: None,
    };
    let finality = kg_export::queue_kg_export_finality_outbox(&db.pool, &finality_request)
        .await
        .expect("queue export finality outbox");
    assert_eq!(
        finality.schema_version,
        KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA
    );
    assert_eq!(finality.inserted_dag_outbox_count, 1);
    assert_eq!(finality.persisted_dag_outbox_count, 1);
    assert_eq!(finality.persisted_route_invalidation_count, 0);
    assert_eq!(finality.persisted_raw_artifact_count, 0);
    assert_eq!(finality.persisted_exo_dag_write_count, 0);
    assert!(!finality.replayed);
    assert_eq!(finality.diagnostics.outbox.subject_kind, "export");
    assert_eq!(finality.diagnostics.outbox.dag_finality_status, "pending");
    assert_eq!(
        finality.diagnostics.outbox.payload_material_class,
        "hash_only_commitment"
    );
    assert!(!finality.diagnostics.outbox.dag_receipt_hash_present);
    assert!(
        !finality
            .diagnostics
            .outbox
            .compensation_receipt_hash_present
    );
    assert!(!finality.diagnostics.outbox.route_invalidation_written);
    assert!(!finality.diagnostics.outbox.direct_exo_dag_write);
    assert!(!finality.diagnostics.outbox.exo_dag_table_mutated);
    assert!(
        finality
            .diagnostics
            .warning_summaries
            .contains(&"not_production_finality".to_owned())
    );
    assert_no_forbidden_material(
        "finality summary",
        &serde_json::to_string(&finality).expect("serialize finality summary"),
    );

    let replay = kg_export::queue_kg_export_finality_outbox(&db.pool, &finality_request)
        .await
        .expect("replay export finality outbox");
    assert!(replay.replayed);
    assert_eq!(replay.outbox_id, finality.outbox_id);
    assert_eq!(replay.dag_payload_hash, finality.dag_payload_hash);
    assert_eq!(
        replay.diagnostics.idempotency_replay.replay_reason,
        "idempotency_key_match"
    );
    assert_eq!(export_dag_outbox_count(&db.pool).await, 1);
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    let outbox_row = export_outbox_row(&db.pool).await;
    assert_eq!(outbox_row.subject_kind, "export");
    assert_eq!(outbox_row.dag_finality_status, "pending");
    assert_eq!(outbox_row.outbox_id, finality.outbox_id);
    assert_eq!(outbox_row.dag_payload_hash, finality.dag_payload_hash);
    assert!(outbox_row.dag_receipt_hash.is_none());
    assert!(outbox_row.compensation_receipt_hash.is_none());
    assert_no_forbidden_material(
        "outbox row",
        &serde_json::to_string(&outbox_row).expect("serialize outbox row"),
    );
    assert_eq!(forbidden_persisted_material_count(&db.pool).await, 0);

    db.cleanup().await;
}

#[tokio::test]
async fn kg_live_loop_rejects_negative_paths_without_partial_growth() {
    let Some(db) = TestDb::new("negative_paths").await else {
        return;
    };

    let (_preview, export, persisted_export) = persist_loop_until_export(&db.pool).await;
    assert_eq!(persisted_export.persisted_route_invalidation_count, 0);
    assert_loop_failure_boundaries(&db.pool, 0, 0).await;

    let cross_scope_request = KgExportFinalityOutboxRequest {
        tenant_id: "other-tenant".to_owned(),
        namespace: "dag-db".to_owned(),
        export_id: export.export_id.clone(),
        requester_did: "did:exo:finality-operator".to_owned(),
        idempotency_key: Some("live-loop-cross-scope-finality".to_owned()),
    };
    assert!(
        matches!(
            kg_export::queue_kg_export_finality_outbox(&db.pool, &cross_scope_request).await,
            Err(KgExportError::Conflict { .. })
        ),
        "cross-tenant export evidence must be rejected before finality queueing"
    );
    assert_loop_failure_boundaries(&db.pool, 0, 0).await;

    let initial_finality_request = finality_request(&export.export_id, "live-loop-finality-key");
    let finality = kg_export::queue_kg_export_finality_outbox(&db.pool, &initial_finality_request)
        .await
        .expect("queue verified export finality evidence");
    assert_eq!(finality.inserted_dag_outbox_count, 1);
    assert_eq!(finality.persisted_route_invalidation_count, 0);
    assert_eq!(finality.persisted_raw_artifact_count, 0);
    assert_eq!(finality.persisted_exo_dag_write_count, 0);
    assert_loop_failure_boundaries(&db.pool, 1, 1).await;

    let mut mismatched_replay = initial_finality_request.clone();
    mismatched_replay.requester_did = "did:exo:other-finality-operator".to_owned();
    assert!(
        matches!(
            kg_export::queue_kg_export_finality_outbox(&db.pool, &mismatched_replay).await,
            Err(KgExportError::Conflict { .. })
        ),
        "finality idempotency replay with changed request material must fail closed"
    );
    assert_loop_failure_boundaries(&db.pool, 1, 1).await;

    sqlx::query("UPDATE dagdb_dag_outbox SET dag_finality_status = 'committed'")
        .execute(&db.pool)
        .await
        .expect("mark repository-test outbox row stale");
    let stale_request = finality_request(&export.export_id, "live-loop-stale-outbox-finality");
    match kg_export::queue_kg_export_finality_outbox(&db.pool, &stale_request).await {
        Err(KgExportError::Conflict { reason }) => {
            assert!(
                reason.contains("not pending"),
                "stale outbox rejection should explain pending-state requirement: {reason}"
            );
        }
        other => panic!("expected stale outbox conflict, got {other:?}"),
    }
    assert_loop_failure_boundaries(&db.pool, 1, 1).await;
    sqlx::query("UPDATE dagdb_dag_outbox SET dag_finality_status = 'pending'")
        .execute(&db.pool)
        .await
        .expect("restore repository-test outbox row pending");

    sqlx::query(
        "UPDATE dagdb_export_challenges SET proof_hash = $1 \
         WHERE challenge_kind = 'citation_index_hash'",
    )
    .bind(hb(0xfe))
    .execute(&db.pool)
    .await
    .expect("tamper challenge proof hash");
    let tampered_request = finality_request(&export.export_id, "live-loop-tampered-proof-finality");
    assert!(
        matches!(
            kg_export::queue_kg_export_finality_outbox(&db.pool, &tampered_request).await,
            Err(KgExportError::Conflict { .. })
        ),
        "tampered export challenge/proof evidence must fail closed"
    );
    assert_loop_failure_boundaries(&db.pool, 1, 1).await;

    let outbox_row = export_outbox_row(&db.pool).await;
    assert_eq!(outbox_row.subject_kind, "export");
    assert_eq!(outbox_row.dag_finality_status, "pending");
    assert_eq!(outbox_row.outbox_id, finality.outbox_id);
    assert_eq!(outbox_row.dag_payload_hash, finality.dag_payload_hash);
    assert_no_forbidden_material(
        "negative-path outbox row",
        &serde_json::to_string(&outbox_row).expect("serialize negative-path outbox row"),
    );

    db.cleanup().await;
}

async fn persist_loop_until_export(
    pool: &PgPool,
) -> (
    KgContextPacketPreview,
    KgPortableExport,
    KgExportPersistedSummary,
) {
    persist_kg_import_report(pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let preview = retrieve_kg_context_packet(pool, &base_request())
        .await
        .expect("retrieve context preview");

    let writeback_report = writeback_report(&preview);
    persist_kg_writeback_report(
        pool,
        &serde_json::to_string(&writeback_report).expect("serialize writeback report"),
    )
    .await
    .expect("persist writeback report");

    let export =
        kg_export::build_kg_portable_export(pool, &export_scope(), std::slice::from_ref(&preview))
            .await
            .expect("build portable export");
    let persisted_export = kg_export::persist_kg_portable_export(pool, &export, "did:exo:exporter")
        .await
        .expect("persist portable export");
    (preview, export, persisted_export)
}

fn finality_request(export_id: &str, idempotency_key: &str) -> KgExportFinalityOutboxRequest {
    KgExportFinalityOutboxRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        export_id: export_id.to_owned(),
        requester_did: "did:exo:finality-operator".to_owned(),
        idempotency_key: Some(idempotency_key.to_owned()),
    }
}

async fn assert_loop_failure_boundaries(
    pool: &PgPool,
    expected_outbox_count: i64,
    expected_finality_idempotency_count: i64,
) {
    assert_eq!(dag_outbox_count(pool).await, expected_outbox_count);
    assert_eq!(export_dag_outbox_count(pool).await, expected_outbox_count);
    assert_eq!(
        finality_idempotency_count(pool).await,
        expected_finality_idempotency_count
    );
    assert_eq!(route_invalidation_count(pool).await, 0);
    assert_eq!(exo_dag_table_count(pool).await, 0);
    assert_eq!(forbidden_persisted_material_count(pool).await, 0);
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
            source_request_id: "source-request-live-loop".into(),
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
            reason_to_remember: "repository-level live loop proof fixture".into(),
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

async fn table_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .expect("count table rows")
}

async fn dag_outbox_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_dag_outbox")
        .fetch_one(pool)
        .await
        .expect("count dag outbox")
}

async fn export_dag_outbox_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_dag_outbox WHERE subject_kind = 'export'")
        .fetch_one(pool)
        .await
        .expect("count export dag outbox")
}

async fn finality_idempotency_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE route_name = 'dagdb.kg_export.finality_outbox.v1'",
    )
    .fetch_one(pool)
    .await
    .expect("count finality idempotency rows")
}

async fn route_invalidation_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_route_invalidations")
        .fetch_one(pool)
        .await
        .expect("count route invalidations")
}

async fn exo_dag_table_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name IN ('dag_nodes', 'dag_committed')",
    )
    .fetch_one(pool)
    .await
    .expect("count exo-dag tables")
}

async fn forbidden_persisted_material_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT \
         (SELECT count(*) FROM dagdb_receipts \
          WHERE receipt_body::text LIKE '%raw_private_payload%' \
             OR receipt_body::text LIKE '%raw_markdown%' \
             OR receipt_body::text LIKE '%raw_model_output%' \
             OR receipt_body::text LIKE '%source_excerpt%' \
             OR receipt_body::text LIKE '%postgres://%' \
             OR receipt_body::text LIKE '%/Users/%') + \
         (SELECT count(*) FROM dagdb_idempotency_keys \
          WHERE response_body::text LIKE '%raw_private_payload%' \
             OR response_body::text LIKE '%raw_markdown%' \
             OR response_body::text LIKE '%raw_model_output%' \
             OR response_body::text LIKE '%source_excerpt%' \
             OR response_body::text LIKE '%postgres://%' \
             OR response_body::text LIKE '%/Users/%') \
         AS forbidden_count",
    )
    .fetch_one(pool)
    .await
    .expect("count forbidden persisted material")
}

#[derive(Debug, Serialize)]
struct ExportOutboxRow {
    outbox_id: String,
    subject_kind: String,
    dag_write_id: String,
    dag_payload_hash: String,
    dag_finality_status: String,
    attempt_count: i32,
    max_attempts: i32,
    next_attempt_at_physical_ms: Option<i64>,
    next_attempt_at_logical: Option<i32>,
    dag_receipt_hash: Option<String>,
    compensation_receipt_hash: Option<String>,
}

async fn export_outbox_row(pool: &PgPool) -> ExportOutboxRow {
    let row = sqlx::query(
        "SELECT encode(outbox_id, 'hex') AS outbox_id, subject_kind, dag_write_id, \
         encode(dag_payload_hash, 'hex') AS dag_payload_hash, dag_finality_status, \
         attempt_count, max_attempts, next_attempt_at_physical_ms, next_attempt_at_logical, \
         encode(dag_receipt_hash, 'hex') AS dag_receipt_hash, \
         encode(compensation_receipt_hash, 'hex') AS compensation_receipt_hash \
         FROM dagdb_dag_outbox WHERE subject_kind = 'export'",
    )
    .fetch_one(pool)
    .await
    .expect("fetch export outbox row");
    ExportOutboxRow {
        outbox_id: row.try_get("outbox_id").expect("outbox_id"),
        subject_kind: row.try_get("subject_kind").expect("subject_kind"),
        dag_write_id: row.try_get("dag_write_id").expect("dag_write_id"),
        dag_payload_hash: row.try_get("dag_payload_hash").expect("dag_payload_hash"),
        dag_finality_status: row
            .try_get("dag_finality_status")
            .expect("dag_finality_status"),
        attempt_count: row.try_get("attempt_count").expect("attempt_count"),
        max_attempts: row.try_get("max_attempts").expect("max_attempts"),
        next_attempt_at_physical_ms: row
            .try_get("next_attempt_at_physical_ms")
            .expect("next_attempt_at_physical_ms"),
        next_attempt_at_logical: row
            .try_get("next_attempt_at_logical")
            .expect("next_attempt_at_logical"),
        dag_receipt_hash: row.try_get("dag_receipt_hash").expect("dag_receipt_hash"),
        compensation_receipt_hash: row
            .try_get("compensation_receipt_hash")
            .expect("compensation_receipt_hash"),
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hb(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn assert_no_forbidden_material(label: &str, json: &str) {
    let value: JsonValue = serde_json::from_str(json).expect("parse JSON material for leak check");
    assert_json_values_exclude_forbidden_material(label, "$", &value);
}

fn assert_json_values_exclude_forbidden_material(label: &str, path: &str, value: &JsonValue) {
    match value {
        JsonValue::String(text) => {
            assert_text_excludes_forbidden_material(label, path, text);
        }
        JsonValue::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                assert_json_values_exclude_forbidden_material(
                    label,
                    &format!("{path}[{index}]"),
                    item,
                );
            }
        }
        JsonValue::Object(map) => {
            for (key, item) in map {
                assert_json_values_exclude_forbidden_material(
                    label,
                    &format!("{path}.{key}"),
                    item,
                );
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

fn assert_text_excludes_forbidden_material(label: &str, path: &str, text: &str) {
    for forbidden in [
        "raw_markdown",
        "raw_markdown_body",
        "raw_private_payload",
        "raw_model_output",
        "source_excerpt",
        "gateway_secret",
        "database_url",
        "postgres://",
        "private_key",
        "/Users/",
        "target/dagdb/kg_export",
    ] {
        assert!(
            !text.contains(forbidden),
            "{label} leaked forbidden material marker {forbidden} at {path}"
        );
    }
}
