#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use exo_dag_db_postgres::{
    KG_EXPORT_DATABASE_URL_ENV, KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA, KgExportBuildInput,
    KgExportError, KgExportFinalityOutboxRequest, KgExportRecord, KgExportScope,
    build_portable_export,
    postgres::{
        DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL, DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_SCHEMA_SQL, kg_export,
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
                "skipping kg_export_finality_outbox postgres test: {KG_EXPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!(
            "dagdb_kg_export_finality_outbox_{label}_{}",
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
async fn export_finality_outbox_missing_database_url_fails_closed() {
    let request = finality_request("tenant-test", "dag-db", &h(0x99));
    let result = kg_export::queue_kg_export_finality_outbox_from_database_url(None, &request).await;
    assert!(matches!(
        result,
        Err(KgExportError::MissingDatabaseUrl { .. })
    ));
}

#[tokio::test]
async fn export_finality_outbox_queues_verified_export_and_replays() {
    let Some(db) = TestDb::new("queue_replay").await else {
        return;
    };
    insert_memory_fixture(&db.pool, "tenant-test", "dag-db").await;
    let export = portable_export("tenant-test", "dag-db");
    let persisted = kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect("persist portable export");
    assert_eq!(dag_outbox_count(&db.pool).await, 0);

    let request = finality_request("tenant-test", "dag-db", &export.export_id);
    let first = kg_export::queue_kg_export_finality_outbox(&db.pool, &request)
        .await
        .expect("queue export finality outbox");
    assert_eq!(
        first.schema_version,
        KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA
    );
    assert_eq!(first.export_id, export.export_id);
    assert_eq!(first.whole_export_hash, export.hashes.whole_export_hash);
    assert_eq!(
        first.latest_receipt_hash,
        persisted.latest_receipt_hash.unwrap()
    );
    assert_eq!(first.export_status, "verified");
    assert_eq!(first.inserted_dag_outbox_count, 1);
    assert_eq!(first.inserted_idempotency_response_count, 1);
    assert_eq!(first.persisted_dag_outbox_count, 1);
    assert_eq!(first.persisted_route_invalidation_count, 0);
    assert_eq!(first.persisted_raw_artifact_count, 0);
    assert_eq!(first.persisted_exo_dag_write_count, 0);
    assert!(!first.replayed);
    assert_eq!(first.diagnostics.evidence.evidence_status, "valid");
    assert_eq!(first.diagnostics.evidence.export_id, export.export_id);
    assert_eq!(
        first.diagnostics.evidence.requester_did,
        "did:exo:finality-operator"
    );
    assert!(first.diagnostics.evidence.committed_export_evidence_checked);
    assert!(
        first
            .diagnostics
            .evidence
            .committed_receipt_evidence_checked
    );
    assert!(first.diagnostics.evidence.export_row_verified);
    assert!(first.diagnostics.evidence.outbox_eligible);
    assert_eq!(
        first.diagnostics.evidence.context_packet_evidence_status,
        "preview_only_not_outbox_material"
    );
    assert_eq!(first.diagnostics.challenge_proof.challenge_count, 5);
    assert_eq!(
        first.diagnostics.challenge_proof.expected_challenge_count,
        5
    );
    assert!(
        first
            .diagnostics
            .challenge_proof
            .challenge_coverage_complete
    );
    assert_eq!(
        first.diagnostics.challenge_proof.challenge_statuses.len(),
        5
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .challenge_statuses
            .get("whole_export_hash")
            .map(String::as_str),
        Some("pending")
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .whole_export_challenge_hash,
        export.hashes.whole_export_hash
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .citation_index_challenge_hash,
        export.hashes.section_hashes["citation_index"]
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .provenance_index_challenge_hash,
        export.hashes.section_hashes["provenance_index"]
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .redaction_summary_challenge_hash,
        export.hashes.section_hashes["redaction_summary"]
    );
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .omission_summary_challenge_hash,
        export.hashes.section_hashes["omission_summary"]
    );
    assert!(first.diagnostics.challenge_proof.readback_verified);
    assert_eq!(
        first.diagnostics.challenge_proof.proof_algorithm,
        "hash_commitment_v1"
    );
    assert!(first.diagnostics.receipt.receipt_row_verified);
    assert!(first.diagnostics.receipt.subject_head_verified);
    assert!(first.diagnostics.receipt.receipt_event_supported);
    assert!(first.diagnostics.receipt.latest_receipt_head_matches);
    assert!(!first.diagnostics.receipt.dag_receipt_hash_present);
    assert!(!first.diagnostics.receipt.compensation_receipt_hash_present);
    assert_eq!(first.diagnostics.outbox.subject_kind, "export");
    assert_eq!(first.diagnostics.outbox.outbox_id, first.outbox_id);
    assert_eq!(
        first.diagnostics.outbox.payload_material_class,
        "hash_only_commitment"
    );
    assert_eq!(first.diagnostics.outbox.dag_finality_status, "pending");
    assert!(!first.diagnostics.outbox.dag_receipt_hash_present);
    assert!(!first.diagnostics.outbox.compensation_receipt_hash_present);
    assert_eq!(first.diagnostics.outbox.retry_attempt_count, 0);
    assert_eq!(first.diagnostics.outbox.max_attempts, 6);
    assert_eq!(
        first.diagnostics.outbox.next_attempt_status,
        "not_scheduled"
    );
    assert!(!first.diagnostics.outbox.direct_exo_dag_write);
    assert!(!first.diagnostics.outbox.exo_dag_table_mutated);
    assert!(!first.diagnostics.outbox.route_invalidation_written);
    assert!(!first.diagnostics.outbox.raw_artifact_persisted);
    assert!(first.diagnostics.idempotency_replay.response_cached);
    assert_eq!(first.diagnostics.idempotency_replay.status_code, 201);
    assert!(
        first
            .diagnostics
            .material_exclusion
            .json_markdown_artifact_absent
    );
    assert!(first.diagnostics.material_exclusion.markdown_body_absent);
    assert!(first.diagnostics.material_exclusion.private_payload_absent);
    assert!(first.diagnostics.material_exclusion.model_output_absent);
    assert!(first.diagnostics.material_exclusion.source_material_absent);
    assert!(first.diagnostics.material_exclusion.gateway_secret_absent);
    assert!(
        first
            .diagnostics
            .material_exclusion
            .database_connection_absent
    );
    assert!(first.diagnostics.material_exclusion.private_key_absent);
    assert!(
        first
            .diagnostics
            .material_exclusion
            .local_absolute_path_absent
    );
    assert!(
        first
            .diagnostics
            .material_exclusion
            .outbox_payload_is_hash_only
    );
    assert!(first.diagnostics.advisory_deferred.gateway_api_deferred);
    assert!(
        first
            .diagnostics
            .advisory_deferred
            .route_invalidation_writes_deferred
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred
            .direct_exo_dag_writes_deferred
    );
    assert!(
        first
            .diagnostics
            .advisory_deferred
            .exo_dag_table_mutation_deferred
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .iter()
            .any(|warning| warning == "raw_export_artifact_not_persisted")
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .iter()
            .any(|warning| warning == "not_production_finality")
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .iter()
            .any(|warning| warning == "exo_dag_table_mutation_deferred")
    );

    let replay = kg_export::queue_kg_export_finality_outbox(&db.pool, &request)
        .await
        .expect("replay export finality outbox");
    assert!(replay.replayed);
    assert_eq!(replay.outbox_id, first.outbox_id);
    assert_eq!(replay.dag_write_id, first.dag_write_id);
    assert_eq!(replay.request_hash, first.request_hash);
    assert_eq!(
        replay.diagnostics.idempotency_replay.replay_reason,
        "idempotency_key_match"
    );
    let mut normalized = replay.clone();
    normalized.replayed = false;
    normalized.diagnostics.idempotency_replay.replayed = false;
    normalized.diagnostics.idempotency_replay.replay_reason = "new_outbox_response".to_owned();
    assert_eq!(first, normalized);

    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(export_dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    let row = export_outbox_row(&db.pool).await;
    assert_eq!(row.subject_kind, "export");
    assert_eq!(row.dag_finality_status, "pending");
    assert_eq!(row.outbox_id, first.outbox_id);
    assert_eq!(row.dag_write_id, first.dag_write_id);
    assert_eq!(row.dag_payload_hash, first.dag_payload_hash);
    assert!(row.dag_receipt_hash.is_none());
    assert!(row.compensation_receipt_hash.is_none());
    assert_eq!(row.attempt_count, 0);
    assert_eq!(row.max_attempts, 6);
    assert!(row.next_attempt_at_physical_ms.is_none());
    assert!(row.next_attempt_at_logical.is_none());

    let summary_json = serde_json::to_string(&first).expect("serialize summary");
    let replay_json = serde_json::to_string(&replay).expect("serialize replay summary");
    assert_eq!(
        summary_json,
        serde_json::to_string(&normalized).expect("serialize normalized replay")
    );
    assert!(replay_json.contains("idempotency_key_match"));
    assert_no_forbidden_material("summary", &summary_json);
    assert_no_forbidden_material("replay summary", &replay_json);
    let row_json = serde_json::to_string(&row).expect("serialize outbox row");
    assert_no_forbidden_material("outbox row", &row_json);
    let idempotency_response_json =
        finality_idempotency_response_json(&db.pool, &first.idempotency_key).await;
    assert_no_forbidden_material("idempotency response", &idempotency_response_json);
    assert_eq!(
        serde_json::from_str::<JsonValue>(&idempotency_response_json)
            .expect("parse idempotency response")["dag_payload_hash"],
        json!(first.dag_payload_hash)
    );

    db.cleanup().await;
}

#[tokio::test]
async fn export_finality_outbox_rejects_bad_evidence_and_mismatched_replay() {
    let Some(db) = TestDb::new("rejects").await else {
        return;
    };
    insert_memory_fixture(&db.pool, "tenant-test", "dag-db").await;
    let export = portable_export("tenant-test", "dag-db");
    kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect("persist portable export");

    let mut request = finality_request("tenant-test", "dag-db", &export.export_id);
    request.idempotency_key = Some("fixed-finality-key".to_owned());
    kg_export::queue_kg_export_finality_outbox(&db.pool, &request)
        .await
        .expect("queue first finality outbox");

    let mut mismatched_replay = request.clone();
    mismatched_replay.requester_did = "did:exo:other-exporter".to_owned();
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &mismatched_replay).await,
        Err(KgExportError::Conflict { .. })
    ));
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);

    let missing = finality_request("tenant-test", "dag-db", &h(0xab));
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &missing).await,
        Err(KgExportError::Conflict { .. })
    ));
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);

    let cross_scope = finality_request("other-tenant", "dag-db", &export.export_id);
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &cross_scope).await,
        Err(KgExportError::Conflict { .. })
    ));
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);

    let unsafe_request = KgExportFinalityOutboxRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        export_id: export.export_id.clone(),
        requester_did: "did:exo:/Users/private".to_owned(),
        idempotency_key: Some("unsafe-finality-key".to_owned()),
    };
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &unsafe_request).await,
        Err(KgExportError::ForbiddenMaterial { .. })
    ));
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);

    let unsafe_idempotency_key = KgExportFinalityOutboxRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        export_id: export.export_id.clone(),
        requester_did: "did:exo:finality-operator".to_owned(),
        idempotency_key: Some("postgres://exo:exo@127.0.0.1/private".to_owned()),
    };
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &unsafe_idempotency_key).await,
        Err(KgExportError::ForbiddenMaterial { .. })
    ));
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);

    sqlx::query("UPDATE dagdb_dag_outbox SET dag_finality_status = 'committed'")
        .execute(&db.pool)
        .await
        .expect("mark existing outbox row committed");
    let mut stale_outbox = finality_request("tenant-test", "dag-db", &export.export_id);
    stale_outbox.idempotency_key = Some("stale-outbox-key".to_owned());
    match kg_export::queue_kg_export_finality_outbox(&db.pool, &stale_outbox).await {
        Err(KgExportError::Conflict { reason }) => {
            assert!(reason.contains("not pending"), "{reason}");
        }
        other => panic!("expected stale outbox conflict, got {other:?}"),
    }
    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);
    sqlx::query("UPDATE dagdb_dag_outbox SET dag_finality_status = 'pending'")
        .execute(&db.pool)
        .await
        .expect("restore outbox row pending");

    sqlx::query(
        "UPDATE dagdb_export_challenges SET proof_hash = $1 \
         WHERE challenge_kind = 'citation_index_hash'",
    )
    .bind(hb(0xfe))
    .execute(&db.pool)
    .await
    .expect("tamper challenge proof");
    let mut bad_challenge = finality_request("tenant-test", "dag-db", &export.export_id);
    bad_challenge.idempotency_key = Some("bad-challenge-key".to_owned());
    assert!(matches!(
        kg_export::queue_kg_export_finality_outbox(&db.pool, &bad_challenge).await,
        Err(KgExportError::Conflict { .. })
    ));

    assert_eq!(dag_outbox_count(&db.pool).await, 1);
    assert_eq!(export_dag_outbox_count(&db.pool).await, 1);
    assert_eq!(finality_idempotency_count(&db.pool).await, 1);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    db.cleanup().await;
}

async fn insert_memory_fixture(pool: &PgPool, tenant_id: &str, namespace: &str) {
    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, 'memory', $4, $5, 1, 'intake_created', 'did:exo:fixture', 1, 0, $6, $7, 1, 0)",
    )
    .bind(hb(0x80))
    .bind(tenant_id)
    .bind(namespace)
    .bind(hb(0x10))
    .bind(hb(0x00))
    .bind(hb(0x81))
    .bind(json!({"fixture": "export_finality_outbox"}))
    .execute(pool)
    .await
    .expect("insert receipt fixture");
    sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'memory', $3, $4, 1, 1, 0)",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(hb(0x10))
    .bind(hb(0x80))
    .execute(pool)
    .await
    .expect("insert subject head fixture");
    sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, \
          owner_did, controller_did, submitted_by_did, title, summary, keywords, risk_class, risk_bp, status, \
          validation_status, council_status, dag_finality_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, 'summary', 'generated', 'retrieval', $4, $5, \
          'did:exo:fixture', 'did:exo:fixture', 'did:exo:fixture', $6, $7, '[]'::jsonb, 'R1', 100, 'approved', \
          'passed', 'not_required', 'pending', $8, 1, 0, 1, 0)",
    )
    .bind(hb(0x10))
    .bind(tenant_id)
    .bind(namespace)
    .bind(hb(0x20))
    .bind(hb(0x21))
    .bind(safe_metadata("Portable export fixture"))
    .bind(safe_metadata("Compact export finality metadata"))
    .bind(hb(0x80))
    .execute(pool)
    .await
    .expect("insert memory fixture");
}

fn portable_export(tenant_id: &str, namespace: &str) -> exo_dag_db_postgres::KgPortableExport {
    let mut memory = record();
    memory.insert("tenant_id".to_owned(), json!(tenant_id));
    memory.insert("namespace".to_owned(), json!(namespace));
    memory.insert("memory_id".to_owned(), json!(h(0x10)));
    memory.insert("payload_hash".to_owned(), json!(h(0x20)));
    memory.insert("source_hash".to_owned(), json!(h(0x21)));
    memory.insert("latest_receipt_hash".to_owned(), json!(h(0x80)));
    memory.insert("title".to_owned(), safe_metadata("Portable export fixture"));
    memory.insert(
        "summary".to_owned(),
        safe_metadata("Compact export finality metadata"),
    );

    let mut receipt = record();
    receipt.insert("tenant_id".to_owned(), json!(tenant_id));
    receipt.insert("namespace".to_owned(), json!(namespace));
    receipt.insert("receipt_hash".to_owned(), json!(h(0x80)));
    receipt.insert("subject_kind".to_owned(), json!("memory"));
    receipt.insert("subject_id".to_owned(), json!(h(0x10)));
    receipt.insert("seq".to_owned(), json!(1));

    let mut subject_head = record();
    subject_head.insert("tenant_id".to_owned(), json!(tenant_id));
    subject_head.insert("namespace".to_owned(), json!(namespace));
    subject_head.insert("subject_kind".to_owned(), json!("memory"));
    subject_head.insert("subject_id".to_owned(), json!(h(0x10)));
    subject_head.insert("latest_receipt_hash".to_owned(), json!(h(0x80)));

    let mut preview = record();
    preview.insert("tenant_id".to_owned(), json!(tenant_id));
    preview.insert("namespace".to_owned(), json!(namespace));
    preview.insert("context_packet_id".to_owned(), json!(h(0x90)));
    preview.insert("preview_only".to_owned(), json!(true));
    preview.insert("body_content_returned".to_owned(), json!(false));

    let mut citation = record();
    citation.insert("citation_handle".to_owned(), json!("kg-export-citation-1"));
    citation.insert("memory_id".to_owned(), json!(h(0x10)));
    citation.insert("latest_receipt_hash".to_owned(), json!(h(0x80)));
    citation.insert("validation_report_ids".to_owned(), json!([]));
    citation.insert("graph_edge_ids".to_owned(), json!([]));

    let mut provenance = record();
    provenance.insert("subject_kind".to_owned(), json!("memory"));
    provenance.insert("subject_id".to_owned(), json!(h(0x10)));
    provenance.insert("receipt_hash".to_owned(), json!(h(0x80)));

    build_portable_export(KgExportBuildInput {
        scope: KgExportScope {
            tenant_id: tenant_id.to_owned(),
            namespace: namespace.to_owned(),
            included_memory_ids: Vec::new(),
            included_graph_styles: Vec::new(),
            included_writeback_idempotency_keys: Vec::new(),
            source_commit_or_repo_ref: Some("test-ref".to_owned()),
            include_preview_context: true,
        },
        memory_records: vec![memory],
        catalog_entries: Vec::new(),
        graph_nodes: Vec::new(),
        graph_edges: Vec::new(),
        similarity_results: Vec::new(),
        canonicalization_decisions: Vec::new(),
        placement_traces: Vec::new(),
        validation_reports: Vec::new(),
        receipts: vec![receipt],
        subject_receipt_heads: vec![subject_head],
        context_packet_previews: vec![preview],
        context_packet_records: Vec::new(),
        route_receipts: Vec::new(),
        writeback_summaries: Vec::new(),
        idempotency_references: Vec::new(),
        citation_index: vec![citation],
        provenance_index: vec![provenance],
    })
    .expect("build portable export")
}

fn finality_request(
    tenant_id: &str,
    namespace: &str,
    export_id: &str,
) -> KgExportFinalityOutboxRequest {
    KgExportFinalityOutboxRequest {
        tenant_id: tenant_id.to_owned(),
        namespace: namespace.to_owned(),
        export_id: export_id.to_owned(),
        requester_did: "did:exo:finality-operator".to_owned(),
        idempotency_key: None,
    }
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

async fn finality_idempotency_response_json(pool: &PgPool, idempotency_key: &str) -> String {
    let value: JsonValue = sqlx::query_scalar(
        "SELECT response_body FROM dagdb_idempotency_keys \
         WHERE route_name = 'dagdb.kg_export.finality_outbox.v1' AND idempotency_key = $1",
    )
    .bind(idempotency_key)
    .fetch_one(pool)
    .await
    .expect("fetch finality idempotency response");
    serde_json::to_string(&value).expect("serialize finality idempotency response")
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

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn record() -> KgExportRecord {
    BTreeMap::new()
}

fn safe_metadata(value: &str) -> JsonValue {
    json!({
        "kind": "safe_metadata",
        "value": value,
        "content_hash": h(0x44)
    })
}

fn hb(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
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
