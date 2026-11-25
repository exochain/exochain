#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use exo_dag_db_postgres::{
    KG_EXPORT_DATABASE_URL_ENV, KG_EXPORT_PERSISTENCE_VERIFICATION_SCHEMA, KgExportBuildInput,
    KgExportError, KgExportRecord, KgExportScope, build_portable_export,
    postgres::{
        DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL, DAGDB_SCHEMA_SQL, kg_export,
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
        let Ok(database_url) = std::env::var(KG_EXPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping kg_export_persistence postgres test: {KG_EXPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_kg_export_persistence_{label}_{}", std::process::id());
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
        sqlx::raw_sql(DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB operational receipt event-type schema");
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
async fn export_persistence_missing_database_url_fails_closed() {
    let result =
        kg_export::persist_kg_portable_export_from_database_url(None, "{}", "did:exo:exporter")
            .await;
    assert!(matches!(
        result,
        Err(KgExportError::MissingDatabaseUrl { .. })
    ));
}

#[tokio::test]
async fn export_persistence_persists_hashes_challenges_receipts_and_replays() {
    let Some(db) = TestDb::new("persist_replay").await else {
        return;
    };
    insert_memory_fixture(&db.pool, "tenant-test", "dag-db").await;
    let export = portable_export("tenant-test", "dag-db");

    let first = kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect("persist portable export");
    assert_eq!(first.schema_version, "dagdb_kg_export_persisted_summary_v1");
    assert_eq!(first.export_id, export.export_id);
    assert_eq!(first.whole_export_hash, export.hashes.whole_export_hash);
    assert_eq!(first.inserted_export_count, 1);
    assert_eq!(first.inserted_challenge_count, 5);
    assert_eq!(first.inserted_receipt_count, 1);
    assert_eq!(first.inserted_subject_receipt_head_count, 1);
    assert_eq!(first.inserted_idempotency_response_count, 1);
    assert_eq!(first.persisted_route_invalidation_count, 0);
    assert_eq!(first.persisted_dag_outbox_count, 0);
    assert_eq!(first.persisted_raw_artifact_count, 0);
    assert_eq!(first.persisted_exo_dag_write_count, 0);
    assert!(first.latest_receipt_hash.is_some());
    assert!(!first.replayed);
    assert_eq!(first.diagnostics.row_counts.export_rows, 1);
    assert_eq!(first.diagnostics.row_counts.challenge_rows, 5);
    assert_eq!(first.diagnostics.row_counts.receipt_rows, 1);
    assert_eq!(first.diagnostics.row_counts.subject_receipt_head_rows, 1);
    assert_eq!(first.diagnostics.row_counts.idempotency_response_rows, 1);
    assert_eq!(first.diagnostics.row_counts.route_invalidation_rows, 0);
    assert_eq!(first.diagnostics.row_counts.dagdb_dag_outbox_rows, 0);
    assert_eq!(first.diagnostics.row_counts.raw_artifact_rows, 0);
    assert_eq!(first.diagnostics.row_counts.exo_dag_rows, 0);
    assert!(first.diagnostics.evidence.committed_memory_evidence_checked);
    assert!(
        first
            .diagnostics
            .evidence
            .committed_receipt_evidence_checked
    );
    assert_eq!(first.diagnostics.evidence.evidence_status, "valid");
    assert_eq!(first.diagnostics.evidence.context_packet_record_count, 0);
    assert_eq!(first.diagnostics.evidence.route_receipt_count, 0);
    assert_eq!(first.diagnostics.evidence.citation_handle_count, 1);
    assert_eq!(first.diagnostics.evidence.provenance_record_count, 1);
    assert_eq!(
        first.diagnostics.evidence.preview_context_status,
        "preview_only"
    );
    assert_eq!(
        first.diagnostics.evidence.route_invalidation_status,
        "not_written"
    );
    assert!(
        first
            .diagnostics
            .evidence
            .evidence_warnings
            .contains(&"preview_context_evidence_not_committed".to_owned())
    );
    assert!(
        first
            .diagnostics
            .section_persistence
            .persisted_row_sections
            .contains(&"dagdb_exports".to_owned())
    );
    assert!(
        first
            .diagnostics
            .section_persistence
            .hash_only_sections
            .contains(&"context_packet_previews".to_owned())
    );
    assert!(
        first
            .diagnostics
            .section_persistence
            .not_persisted_sections
            .contains(&"json_export_artifact".to_owned())
    );
    assert!(!first.diagnostics.section_persistence.raw_artifact_persisted);
    assert_eq!(
        first.diagnostics.section_persistence.section_hash_count,
        u32::try_from(export.hashes.section_hashes.len()).expect("section hash count fits")
    );
    assert_eq!(first.diagnostics.challenge_proof.challenge_count, 5);
    assert!(first.diagnostics.challenge_proof.coverage_complete);
    assert_eq!(first.diagnostics.challenge_proof.challenge_hashes.len(), 5);
    assert_eq!(
        first
            .diagnostics
            .challenge_proof
            .challenge_hashes
            .get("whole_export_hash"),
        Some(&export.hashes.whole_export_hash)
    );
    assert!(
        first
            .diagnostics
            .challenge_proof
            .covered_hash_sections
            .contains(&"citation_index_hash".to_owned())
    );
    assert_eq!(
        first.diagnostics.challenge_proof.proof_algorithm,
        "hash_commitment_v1"
    );
    assert_eq!(first.diagnostics.receipt.receipt_subject_kind, "export");
    assert_eq!(
        first.diagnostics.receipt.receipt_event_type,
        "dagdb_export_completed"
    );
    assert!(first.diagnostics.receipt.latest_receipt_hash.is_some());
    assert!(first.diagnostics.receipt.subject_head_written);
    assert_eq!(
        first.diagnostics.receipt.dag_finality_status,
        "pending_no_dag_outbox"
    );
    assert!(
        !first
            .diagnostics
            .receipt
            .receipt_body_raw_artifact_persisted
    );
    assert!(!first.diagnostics.receipt.route_invalidation_receipt_written);
    assert!(first.diagnostics.idempotency_replay.response_cached);
    assert_eq!(first.diagnostics.idempotency_replay.status_code, 201);
    assert_eq!(
        first
            .diagnostics
            .advisory_deferred
            .route_invalidation_status,
        "advisory_not_written"
    );
    assert!(first.diagnostics.advisory_deferred.gateway_api_deferred);
    assert!(first.diagnostics.advisory_deferred.graph_explorer_deferred);
    assert!(
        first
            .diagnostics
            .advisory_deferred
            .dagdb_dag_outbox_deferred
    );
    assert!(first.diagnostics.advisory_deferred.exo_dag_writes_deferred);
    assert!(
        first
            .diagnostics
            .advisory_deferred
            .broad_product_export_surface_deferred
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
            .any(|warning| warning == "dagdb_dag_outbox_write_deferred")
    );
    assert!(
        first
            .diagnostics
            .warning_summaries
            .iter()
            .any(|warning| warning == "broad_product_export_surface_deferred")
    );

    let verification =
        kg_export::verify_persisted_kg_export(&db.pool, &export, &first, "did:exo:exporter")
            .await
            .expect("verify persisted export rows");
    assert_eq!(
        verification.schema_version,
        KG_EXPORT_PERSISTENCE_VERIFICATION_SCHEMA
    );
    assert_eq!(verification.export_id, first.export_id);
    assert_eq!(verification.idempotency_key, first.idempotency_key);
    assert_eq!(verification.request_hash, first.request_hash);
    assert_eq!(verification.whole_export_hash, first.whole_export_hash);
    assert_eq!(verification.latest_receipt_hash, first.latest_receipt_hash);
    assert!(verification.verified);
    assert!(verification.deterministic_readback);
    assert!(verification.export_row_verified);
    assert!(verification.challenge_rows_verified);
    assert!(verification.receipt_row_verified);
    assert!(verification.subject_head_verified);
    assert!(verification.idempotency_response_verified);
    assert!(verification.persisted_summary_matches_idempotency_response);
    assert_eq!(verification.row_counts.export_rows, 1);
    assert_eq!(verification.row_counts.challenge_rows, 5);
    assert_eq!(verification.row_counts.receipt_rows, 1);
    assert_eq!(verification.row_counts.subject_receipt_head_rows, 1);
    assert_eq!(verification.row_counts.idempotency_response_rows, 1);
    assert_eq!(verification.route_invalidation_rows, 0);
    assert_eq!(verification.dagdb_dag_outbox_rows, 0);
    assert_eq!(verification.raw_artifact_rows, 0);
    assert_eq!(verification.exo_dag_rows, 0);
    assert!(verification.challenge_coverage_complete);
    assert_eq!(verification.challenge_hashes.len(), 5);
    assert_eq!(
        verification.challenge_hashes.get("whole_export_hash"),
        Some(&export.hashes.whole_export_hash)
    );
    assert_eq!(verification.preview_context_status, "preview_only");
    assert_eq!(
        verification.route_invalidation_status,
        "advisory_not_written"
    );
    assert!(
        verification
            .warning_summaries
            .iter()
            .any(|warning| warning == "raw_artifact_rows_verified_absent")
    );
    assert!(
        verification
            .warning_summaries
            .iter()
            .any(|warning| warning == "dagdb_dag_outbox_rows_verified_absent")
    );
    assert_eq!(
        verification,
        kg_export::verify_persisted_kg_export(&db.pool, &export, &first, "did:exo:exporter")
            .await
            .expect("verify persisted export rows again")
    );

    let replay = kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect("replay portable export");
    assert!(replay.replayed);
    assert_eq!(replay.export_id, first.export_id);
    assert_eq!(replay.request_hash, first.request_hash);
    assert_eq!(
        replay.diagnostics.idempotency_replay.replay_reason,
        "idempotency_key_match"
    );
    let mut normalized_replay = replay.clone();
    normalized_replay.replayed = false;
    normalized_replay.diagnostics.idempotency_replay.replayed = false;
    normalized_replay
        .diagnostics
        .idempotency_replay
        .replay_reason = "new_persisted_response".to_owned();
    assert_eq!(first, normalized_replay);
    assert_eq!(
        verification,
        kg_export::verify_persisted_kg_export(&db.pool, &export, &replay, "did:exo:exporter")
            .await
            .expect("verify replayed persisted export rows")
    );

    assert_eq!(table_count(&db.pool, "dagdb_exports").await, 1);
    assert_eq!(table_count(&db.pool, "dagdb_export_challenges").await, 5);
    assert_eq!(export_receipt_count(&db.pool).await, 1);
    assert_eq!(export_subject_head_count(&db.pool).await, 1);
    assert_eq!(idempotency_count(&db.pool).await, 1);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(dag_outbox_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    let summary_json = serde_json::to_string(&first).expect("serialize summary");
    assert!(!summary_json.contains("raw_markdown"));
    assert!(!summary_json.contains("raw_private_payload"));
    assert!(!summary_json.contains("raw_model_output"));
    assert!(!summary_json.contains("postgres://"));
    assert!(!summary_json.contains("/Users/"));

    db.cleanup().await;
}

#[tokio::test]
async fn export_persistence_rejects_unsafe_scope_and_mismatched_replay() {
    let Some(db) = TestDb::new("rejects").await else {
        return;
    };
    insert_memory_fixture(&db.pool, "tenant-test", "dag-db").await;
    let export = portable_export("tenant-test", "dag-db");
    let idempotency_key =
        kg_export::export_persistence_idempotency_key(&export, "did:exo:exporter")
            .expect("derive key");
    let first = kg_export::persist_kg_portable_export_with_idempotency_key(
        &db.pool,
        &export,
        "did:exo:exporter",
        &idempotency_key,
    )
    .await
    .expect("persist portable export");

    let mut tampered = export.clone();
    tampered.hashes.whole_export_hash = h(0xee);
    let replay_result = kg_export::persist_kg_portable_export_with_idempotency_key(
        &db.pool,
        &tampered,
        "did:exo:exporter",
        &idempotency_key,
    )
    .await;
    assert!(matches!(replay_result, Err(KgExportError::Conflict { .. })));
    let verify_result =
        kg_export::verify_persisted_kg_export(&db.pool, &tampered, &first, "did:exo:exporter")
            .await;
    assert!(matches!(verify_result, Err(KgExportError::Conflict { .. })));

    let mut cross_scope = export.clone();
    cross_scope.export_scope.tenant_id = "other-tenant".into();
    let scope_result =
        kg_export::persist_kg_portable_export(&db.pool, &cross_scope, "did:exo:exporter").await;
    assert!(matches!(
        scope_result,
        Err(KgExportError::InvalidScope { .. })
    ));

    let mut unsafe_json = serde_json::to_value(&export).expect("export to value");
    unsafe_json["memory_records"][0]["raw_markdown"] = json!("unsafe");
    let unsafe_result = kg_export::persist_kg_portable_export_json(
        &db.pool,
        &serde_json::to_string(&unsafe_json).expect("unsafe export json"),
        "did:exo:exporter",
    )
    .await;
    assert!(matches!(
        unsafe_result,
        Err(KgExportError::ForbiddenMaterial { .. })
    ));
    assert_eq!(table_count(&db.pool, "dagdb_exports").await, 1);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(dag_outbox_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn export_evidence_read_is_tenant_scoped_cross_tenant_by_hash_fails_closed() {
    // GAP-012 P1-E: the by-hash evidence read is now scoped by tenant_id +
    // namespace. A caller holding another tenant's globally-unique memory_id must
    // not be able to bind it as export evidence: the scoped read returns
    // not-found and the export fails closed, while a same-tenant export over the
    // identical hash still succeeds.
    let Some(db) = TestDb::new("evidence_tenant_scope").await else {
        return;
    };

    // The memory row (memory_id 0x10) exists only under tenant-b / namespace-b.
    insert_memory_fixture(&db.pool, "tenant-b", "namespace-b").await;

    // tenant-a presents an export referencing that same memory_id hash. Before
    // the predicate hardening the row would have been fetched and rejected only
    // by a Rust-side comparison; now the scoped read never sees the cross-tenant
    // row and the export fails closed as not-found.
    let cross_tenant = portable_export("tenant-a", "namespace-a");
    let cross_result =
        kg_export::persist_kg_portable_export(&db.pool, &cross_tenant, "did:exo:exporter").await;
    assert!(
        matches!(cross_result, Err(KgExportError::Conflict { .. })),
        "cross-tenant by-hash evidence read must fail closed, got {cross_result:?}"
    );
    // No tenant-a export row was persisted; tenant-b's row is untouched.
    assert_eq!(table_count(&db.pool, "dagdb_exports").await, 0);
    assert_eq!(table_count(&db.pool, "dagdb_memory_objects").await, 1);
    let surviving_tenant: String = sqlx::query_scalar("SELECT tenant_id FROM dagdb_memory_objects")
        .fetch_one(&db.pool)
        .await
        .expect("load surviving memory tenant");
    assert_eq!(surviving_tenant, "tenant-b");

    // The same export, scoped to the owning tenant, still persists over the
    // identical memory_id hash — proving the predicate is an isolation boundary,
    // not a regression of legitimate same-tenant reads.
    let same_tenant = portable_export("tenant-b", "namespace-b");
    let same_result =
        kg_export::persist_kg_portable_export(&db.pool, &same_tenant, "did:exo:exporter")
            .await
            .expect("same-tenant export over identical hash still persists");
    assert_eq!(same_result.inserted_export_count, 1);
    assert_eq!(table_count(&db.pool, "dagdb_exports").await, 1);

    db.cleanup().await;
}

#[tokio::test]
async fn export_persistence_replay_fails_typed_on_incompatible_cached_summary() {
    let Some(db) = TestDb::new("replay_old_shape").await else {
        return;
    };
    insert_memory_fixture(&db.pool, "tenant-test", "dag-db").await;
    let export = portable_export("tenant-test", "dag-db");
    kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect("persist portable export");

    sqlx::query(
        "UPDATE dagdb_idempotency_keys \
         SET response_body = jsonb_set(response_body, '{schema_version}', '\"dagdb_kg_export_persisted_summary_v0\"') \
         WHERE route_name = 'dagdb.kg_export.persisted.v1'",
    )
    .execute(&db.pool)
    .await
    .expect("rewrite cached schema version");
    let stale_schema = kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect_err("stale cached schema version must fail closed");
    assert!(matches!(
        stale_schema,
        KgExportError::IncompatibleCachedResponse { .. }
    ));
    assert!(
        stale_schema
            .to_string()
            .starts_with("kg_export_incompatible_cached_response"),
        "stale schema replay must use the stable error code: {stale_schema}"
    );

    sqlx::query(
        "UPDATE dagdb_idempotency_keys \
         SET response_body = (response_body - 'persisted_dag_outbox_count') \
             || jsonb_build_object('schema_version', 'dagdb_kg_export_persisted_summary_v1') \
         WHERE route_name = 'dagdb.kg_export.persisted.v1'",
    )
    .execute(&db.pool)
    .await
    .expect("rewrite cached row to old summary shape");
    let old_shape = kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
        .await
        .expect_err("old-shape cached summary must fail closed");
    assert!(matches!(
        old_shape,
        KgExportError::IncompatibleCachedResponse { .. }
    ));
    assert!(
        old_shape
            .to_string()
            .starts_with("kg_export_incompatible_cached_response"),
        "old-shape replay must use the stable error code: {old_shape}"
    );
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
    .bind(json!({"fixture": "export_persistence"}))
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
    .bind(safe_metadata("Compact export persistence metadata"))
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
        safe_metadata("Compact export persistence metadata"),
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

    let mut writeback = record();
    writeback.insert("tenant_id".to_owned(), json!(tenant_id));
    writeback.insert("namespace".to_owned(), json!(namespace));
    writeback.insert("proposal_id".to_owned(), json!(h(0x91)));
    writeback.insert("candidate_id".to_owned(), json!(h(0x92)));
    writeback.insert("idempotency_key".to_owned(), json!(h(0x93)));
    writeback.insert(
        "schema_version".to_owned(),
        json!("dagdb_kg_writeback_persisted_summary_v1"),
    );

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
        writeback_summaries: vec![writeback],
        idempotency_references: Vec::new(),
        citation_index: vec![citation],
        provenance_index: vec![provenance],
    })
    .expect("build portable export")
}

async fn table_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("count {table}: {err}"))
}

async fn export_receipt_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_receipts WHERE subject_kind = 'export'")
        .fetch_one(pool)
        .await
        .expect("count export receipts")
}

async fn export_subject_head_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_subject_receipt_heads WHERE subject_kind = 'export'",
    )
    .fetch_one(pool)
    .await
    .expect("count export subject heads")
}

async fn idempotency_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys WHERE route_name = 'dagdb.kg_export.persisted.v1'",
    )
    .fetch_one(pool)
    .await
    .expect("count export idempotency rows")
}

async fn route_invalidation_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_graph_route_invalidations")
        .fetch_one(pool)
        .await
        .expect("count route invalidations")
}

async fn dag_outbox_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_dag_outbox")
        .fetch_one(pool)
        .await
        .expect("count dag outbox")
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
