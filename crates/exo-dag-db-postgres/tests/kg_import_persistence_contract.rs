#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::Hash256;
use exo_dag_db_api::MemoryGraphStyle;
use exo_dag_db_postgres::{
    deterministic_layer_edge_id, deterministic_layer_id, deterministic_layer_membership_id,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        KG_IMPORT_PERSISTED_ROUTE_NAME, KG_IMPORT_PERSISTED_SUMMARY_SCHEMA, KgImportDryRunReport,
        required_trace,
    },
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        kg_import::{
            KgImportPersistenceError, persist_kg_import_report,
            persist_kg_import_report_from_database_url,
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
            eprintln!("skipping kg_import postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set");
            return None;
        };
        let schema = format!("dagdb_kg_import_{label}_{}", std::process::id());
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
async fn kg_import_from_missing_database_url_fails_closed() {
    let result = persist_kg_import_report_from_database_url(None, "{}").await;
    assert!(matches!(
        result,
        Err(KgImportPersistenceError::MissingDatabaseUrl { .. })
    ));
}

#[tokio::test]
async fn kg_import_from_database_url_initializes_pool_and_closes_it() {
    let Some(db) = TestDb::new("from_database_url").await else {
        return;
    };
    let database_url = std::env::var(KG_IMPORT_DATABASE_URL_ENV)
        .expect("database URL must exist when TestDb was created");
    let scoped_url = database_url_with_search_path(&database_url, &db.schema);

    let summary =
        persist_kg_import_report_from_database_url(Some(&scoped_url), &base_report().to_string())
            .await
            .expect("persist through explicit database URL");
    assert!(!summary.replayed);
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 1);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_persists_supported_sections_and_replays_idempotently() {
    let Some(db) = TestDb::new("supported_sections").await else {
        return;
    };
    let report = base_report();
    let report_json = report.to_string();

    let first = persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("first persisted KG import");
    assert_eq!(first.schema_version, KG_IMPORT_PERSISTED_SUMMARY_SCHEMA);
    assert!(!first.replayed);
    assert_eq!(first.inserted_memory_count, 2);
    assert_eq!(first.inserted_catalog_count, 2);
    assert_eq!(first.inserted_graph_node_count, 2);
    assert_eq!(first.inserted_graph_edge_count, 1);
    assert_eq!(first.inserted_layer_count, 0);
    assert_eq!(first.inserted_layer_membership_count, 0);
    assert_eq!(first.inserted_layer_edge_count, 0);
    assert_eq!(first.inserted_validation_report_count, 2);
    assert_eq!(first.inserted_placement_decision_count, 2);
    assert_eq!(first.inserted_placement_trace_count, 2);
    assert_eq!(first.inserted_receipt_count, 7);

    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_nodes").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 1);
    assert_eq!(row_count(&db.pool, "dagdb_validation_reports").await, 2);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_canonicalization_decisions").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_placement_traces").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 9);
    assert_eq!(row_count(&db.pool, "dagdb_subject_receipt_heads").await, 7);
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_request_submitted").await,
        1
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_granted").await,
        1
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_import_completed").await,
        1
    );
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    let second = persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("idempotent KG import replay");
    assert!(second.replayed);
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 9);
    assert_eq!(row_count(&db.pool, "dagdb_subject_receipt_heads").await, 7);
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_request_submitted").await,
        1
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_granted").await,
        1
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_import_completed").await,
        1
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_persists_layer_sections_and_replays_idempotently() {
    let Some(db) = TestDb::new("layer_sections").await else {
        return;
    };
    let report = layered_report();
    let report_json = report.to_string();

    let first = persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("first layered KG import");
    assert!(!first.replayed);
    assert_eq!(first.inserted_layer_count, 2);
    assert_eq!(first.inserted_layer_membership_count, 2);
    assert_eq!(first.inserted_layer_edge_count, 1);
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 2);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 1);

    let second = persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("layered KG import replay");
    assert!(second.replayed);
    assert_eq!(row_count(&db.pool, "dagdb_graph_layers").await, 2);
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layer_memberships").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_layer_edges").await, 1);

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_persists_deep_detail_summary_tier() {
    // PRD-D3 (D3-S4): a memory record carrying a deep tier persists the nullable
    // dagdb_memory_objects.deep_detail_summary column with the distilled deep text.
    let Some(db) = TestDb::new("deep_tier_persist").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_memory_records"][0]["deep_detail_summary"] =
        safe("deep detail tier: the fuller governed fact set served on drilldown");
    let summary = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("import with deep tier");
    assert!(!summary.replayed);

    // The deep tier column is populated for 0x10 and its text matches.
    let deep_text: Option<String> = sqlx::query_scalar(
        "SELECT deep_detail_summary->>'text' FROM dagdb_memory_objects \
         WHERE memory_id = decode($1, 'hex')",
    )
    .bind(h(0x10))
    .fetch_one(&db.pool)
    .await
    .expect("read deep tier column");
    assert_eq!(
        deep_text.as_deref(),
        Some("deep detail tier: the fuller governed fact set served on drilldown")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_without_deep_detail_summary_persists_null() {
    // PRD-D3 (D3-S4): nullable back-compat — a record WITHOUT a deep tier persists
    // with deep_detail_summary IS NULL and stays valid (the column was just added).
    let Some(db) = TestDb::new("deep_tier_nullable").await else {
        return;
    };
    let report = base_report();
    assert!(
        report["proposed_memory_records"][0]
            .get("deep_detail_summary")
            .is_none(),
        "fixture must omit the deep tier for the back-compat case"
    );
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("import without deep tier stays valid");

    let null_count = scalar_count_where(
        &db.pool,
        "dagdb_memory_objects",
        "deep_detail_summary IS NULL",
    )
    .await;
    assert_eq!(
        null_count,
        row_count(&db.pool, "dagdb_memory_objects").await,
        "every record without a deep tier persists deep_detail_summary as NULL"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_rejects_poisoned_deep_detail_summary_fail_closed() {
    // PRD-D3 (D3-S4): a poisoned deep tier is rejected fail-closed at ingestion by
    // the SAME server-side screen as the short tier (reject_forbidden_report_json
    // walks the whole report, including this field, against FORBIDDEN_VALUE_FRAGMENTS).
    // Each forbidden class the short tier rejects, the deep tier rejects too;
    // nothing is persisted.
    for poison in [
        "deep detail leaks /Users/me/secret.md",
        "deep detail sets a postgres:// connection",
        "deep detail sets database_url to a connection string",
    ] {
        let Some(db) = TestDb::new("deep_tier_poison").await else {
            return;
        };
        let mut report = base_report();
        report["proposed_memory_records"][0]["deep_detail_summary"] = safe(poison);
        let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
        assert!(
            matches!(result, Err(KgImportPersistenceError::Report(_))),
            "poisoned deep tier must be rejected fail-closed: {poison:?} (got {result:?})"
        );
        assert_eq!(
            row_count(&db.pool, "dagdb_memory_objects").await,
            0,
            "a rejected import persists nothing"
        );
        db.cleanup().await;
    }
}

#[tokio::test]
async fn kg_import_authors_content_bearing_layer_aggregate_summaries() {
    // PRD-D2 (D2-S3): import-time layer derivation authors a content-bearing
    // aggregate root summary on each layer with members, persisted to
    // dagdb_graph_layers.aggregate_summary; re-running is byte-identical.
    let Some(db) = TestDb::new("layer_aggregate_author").await else {
        return;
    };
    let report_json = layered_report().to_string();
    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("first layered import authors aggregates");

    // The depth-1 knowledge-graph layer has a member (0x11) whose title/summary are
    // content-bearing, so its aggregate is populated and carries the member's text.
    let kg_layer = layer_id("root/knowledge-graph", 1);
    let aggregate: Option<JsonValue> = sqlx::query_scalar(
        "SELECT aggregate_summary FROM dagdb_graph_layers \
         WHERE layer_id = decode($1, 'hex')",
    )
    .bind(&kg_layer)
    .fetch_one(&db.pool)
    .await
    .expect("read aggregate_summary column");
    let aggregate = aggregate.expect("depth-1 layer carries an aggregate");
    let summary_text = aggregate["summary"]["text"]
        .as_str()
        .expect("aggregate summary text");
    assert!(
        !summary_text.is_empty(),
        "aggregate must be content-bearing, got empty"
    );
    assert!(
        summary_text.contains("01_Project_Brief"),
        "aggregate must distill the member's content, got {summary_text:?}"
    );
    // The aggregate object is the {title, summary} shape the rollup read parses.
    assert!(aggregate.get("title").is_some() && aggregate.get("summary").is_some());

    // Byte-identical re-derivation: a second import (replay) leaves the persisted
    // aggregate unchanged byte-for-byte.
    let before = aggregate.clone();
    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("replay import");
    let after: Option<JsonValue> = sqlx::query_scalar(
        "SELECT aggregate_summary FROM dagdb_graph_layers \
         WHERE layer_id = decode($1, 'hex')",
    )
    .bind(&kg_layer)
    .fetch_one(&db.pool)
    .await
    .expect("re-read aggregate_summary column");
    assert_eq!(
        after.expect("aggregate still present"),
        before,
        "re-running derivation must be byte-identical"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_poisoned_layer_member_never_reaches_persisted_aggregate() {
    // PRD-D2 (D2-S3): a poisoned member's material can never reach a persisted
    // aggregate. The whole-report screen rejects the forbidden fragment before the
    // aggregate is even authored, so the import fails closed and nothing persists.
    let Some(db) = TestDb::new("layer_aggregate_poison").await else {
        return;
    };
    let mut report = layered_report();
    // Poison the summary of memory 0x11 (the depth-1 layer's member).
    report["proposed_memory_records"][1]["summary"] =
        safe("member summary leaking postgres://user:pw@host/db");
    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(
        matches!(result, Err(KgImportPersistenceError::Report(_))),
        "poisoned layer member must be rejected fail-closed (got {result:?})"
    );
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_layers").await,
        0,
        "a rejected import persists no layer, hence no aggregate"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_existing_supported_rows_with_new_batch_are_not_duplicated() {
    let Some(db) = TestDb::new("existing_rows_replay").await else {
        return;
    };
    let report = base_report();
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("first persisted KG import");

    let mut new_batch = report;
    new_batch["batch_id"] = json!(h(0x02));
    let second = persist_kg_import_report(&db.pool, &new_batch.to_string())
        .await
        .expect("existing rows with matching material should not conflict");

    assert!(!second.replayed);
    assert_eq!(second.inserted_memory_count, 0);
    assert_eq!(second.inserted_catalog_count, 0);
    assert_eq!(second.inserted_receipt_count, 1);
    assert_eq!(second.inserted_graph_node_count, 0);
    assert_eq!(second.inserted_graph_edge_count, 0);
    assert_eq!(second.inserted_validation_report_count, 0);
    assert_eq!(second.inserted_placement_decision_count, 0);
    assert_eq!(second.inserted_placement_trace_count, 0);
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_nodes").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 1);
    assert_eq!(row_count(&db.pool, "dagdb_validation_reports").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 12);
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_request_submitted").await,
        2
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_approval_granted").await,
        2
    );
    assert_eq!(
        receipt_event_count(&db.pool, "dagdb_import_completed").await,
        2
    );
    assert_eq!(
        row_count(&db.pool, "dagdb_graph_canonicalization_decisions").await,
        2
    );
    assert_eq!(row_count(&db.pool, "dagdb_graph_placement_traces").await, 2);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 2);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_existing_row_mismatches_fail_closed_by_section() {
    assert_existing_row_mismatch(
        "mismatch_memory",
        "UPDATE dagdb_memory_objects SET namespace = 'other-namespace' \
         WHERE memory_id = decode($1, 'hex')",
        0x10,
        "existing memory row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_catalog",
        "UPDATE dagdb_catalog_entries SET namespace = 'other-namespace' \
         WHERE catalog_id = decode($1, 'hex')",
        0x30,
        "existing dagdb_catalog_entries row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_validation",
        "UPDATE dagdb_validation_reports SET namespace = 'other-namespace' \
         WHERE validation_report_id = decode($1, 'hex')",
        0x70,
        "existing dagdb_validation_reports row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_graph_node",
        "UPDATE dagdb_graph_nodes SET namespace = 'other-namespace' \
         WHERE graph_node_id = decode($1, 'hex')",
        0x40,
        "existing dagdb_graph_nodes row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_graph_edge",
        "UPDATE dagdb_graph_edges SET edge_kind = 'supports' \
         WHERE graph_edge_id = decode($1, 'hex')",
        0x50,
        "existing dagdb_graph_edges row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_canonicalization",
        "UPDATE dagdb_graph_canonicalization_decisions SET decision_kind = 'related' \
         WHERE decision_id = decode($1, 'hex')",
        0x60,
        "existing dagdb_graph_canonicalization_decisions row mismatch",
    )
    .await;
    assert_existing_row_mismatch(
        "mismatch_placement_trace",
        "UPDATE dagdb_graph_placement_traces SET completed = false \
         WHERE input_memory_id = decode($1, 'hex')",
        0x10,
        "existing dagdb_graph_placement_traces row mismatch",
    )
    .await;
}

#[tokio::test]
async fn kg_import_replays_when_non_persisted_advisory_material_changes() {
    let Some(db) = TestDb::new("advisory_replay").await else {
        return;
    };
    let report = base_report();
    let first = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("first persisted KG import");
    assert!(!first.replayed);

    let mut advisory_changed = report;
    advisory_changed["placement_governance_summary"] = json!({
        "advisory_only": true,
        "reason": "synthetic non-persisted replay fixture"
    });
    let second = persist_kg_import_report(&db.pool, &advisory_changed.to_string())
        .await
        .expect("advisory-only request material should replay");
    assert!(second.replayed);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 1);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_changed_persisted_material_conflicts_with_same_idempotency_key() {
    let Some(db) = TestDb::new("persisted_material_conflict").await else {
        return;
    };
    let mut report = base_report();
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("first persisted KG import");

    report["proposed_memory_records"][0]["summary"] = safe("changed persisted summary");
    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(
        matches!(
            result,
            Err(KgImportPersistenceError::Conflict { ref reason }) if reason == "idempotency_key_conflict"
        ),
        "changed persisted material must fail closed, got {result:?}"
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_legacy_raw_report_idempotency_row_does_not_block_current_replay_key() {
    let Some(db) = TestDb::new("legacy_raw_hash").await else {
        return;
    };
    let report = base_report();
    let parsed = KgImportDryRunReport::parse_json(&report.to_string()).expect("valid report");
    let legacy_idempotency_key = parsed.idempotency_key().expect("legacy idempotency key");
    let legacy_request_hash = [0xaa_u8; 32];
    let legacy_response_hash = [0xbb_u8; 32];
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, \
          status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 201, false, 1, 0, 86400001, 0)",
    )
    .bind("tenant-test")
    .bind("dag-db")
    .bind(KG_IMPORT_PERSISTED_ROUTE_NAME)
    .bind(&legacy_idempotency_key)
    .bind(legacy_request_hash.as_slice())
    .bind(legacy_response_hash.as_slice())
    .bind(json!({
        "schema_version": KG_IMPORT_PERSISTED_SUMMARY_SCHEMA,
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "batch_id": h(0x01),
        "idempotency_key": legacy_idempotency_key,
        "replayed": false,
        "inserted_memory_count": 0,
        "inserted_catalog_count": 0,
        "inserted_graph_node_count": 0,
        "inserted_graph_edge_count": 0,
        "inserted_validation_report_count": 0,
        "inserted_placement_decision_count": 0,
        "inserted_placement_trace_count": 0,
        "inserted_receipt_count": 0,
        "skipped_advisory_section_count": 0
    }))
    .execute(&db.pool)
    .await
    .expect("insert legacy idempotency row");

    let first = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("legacy raw-hash row must not block current persist");
    assert!(!first.replayed);
    let second = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("current idempotency row should replay");
    assert!(second.replayed);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 2);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_missing_supported_receipt_rolls_back_prior_writes() {
    let Some(db) = TestDb::new("missing_receipt").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_receipt_intents"]
        .as_array_mut()
        .expect("fixture receipts are an array")
        .retain(|receipt| receipt["subject_id"] != json!(h(0x30)));

    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(
        matches!(
            result,
            Err(KgImportPersistenceError::UnsupportedSection { ref section })
                if section.starts_with("missing supported receipt intent catalog:")
        ),
        "missing supported receipt must fail closed, got {result:?}"
    );
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_unknown_graph_endpoint_conflict_rolls_back_prior_writes() {
    let Some(db) = TestDb::new("unknown_graph_endpoint").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_graph_edges"][0]["to_memory_id"] = json!(h(0x99));

    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(
        matches!(
            result,
            Err(KgImportPersistenceError::Conflict { ref reason })
                if reason.starts_with("graph edge references unknown endpoint")
        ),
        "unknown graph endpoint must fail closed, got {result:?}"
    );
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_catalog_entries").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_validation_reports").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_graph_nodes").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_rolls_back_on_unsupported_schema() {
    let Some(db) = TestDb::new("bad_schema").await else {
        return;
    };
    let mut report = base_report();
    report["schema_version"] = json!("unsupported");
    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(matches!(result, Err(KgImportPersistenceError::Report(_))));
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_rolls_back_on_dangerous_path() {
    let Some(db) = TestDb::new("dangerous_path").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_memory_records"][0]["source_path"] = json!("../escape.md");
    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(matches!(result, Err(KgImportPersistenceError::Report(_))));
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_receipts").await, 0);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_unresolved_links_do_not_create_edges() {
    let Some(db) = TestDb::new("unresolved_links").await else {
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
    report["proposed_governance_reviews"] = json!([
        {
            "review_id": h(0xc0),
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "status": "needs_review",
            "reason": "synthetic unresolved wikilink"
        }
    ]);

    let summary = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("unresolved links import as review-only");
    assert_eq!(summary.inserted_graph_edge_count, 0);
    assert!(summary.skipped_advisory_section_count >= 2);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 0);
    assert_eq!(row_count(&db.pool, "dagdb_memory_objects").await, 2);
    db.cleanup().await;
}

#[tokio::test]
async fn kg_import_duplicate_content_hash_required_edge_persists_safely() {
    let Some(db) = TestDb::new("duplicates").await else {
        return;
    };
    let mut report = base_report();
    report["proposed_graph_edges"] = json!([]);
    report["proposed_memory_records"][1]["payload_hash"] =
        report["proposed_memory_records"][0]["payload_hash"].clone();
    report["proposed_required_edges"] = json!([
        {
            "required_edge_id": h(0x55),
            "tenant_id": "tenant-test",
            "namespace": "dag-db",
            "graph_style": "canonical_memory_graph",
            "from_memory_id": h(0x11),
            "to_memory_id": h(0x10),
            "edge_kind": "duplicate_of",
            "status": "proposed"
        }
    ]);
    report["proposed_placement_decisions"][1]["canonicalization_decision"]["decision_kind"] =
        json!("exact_duplicate");
    report["proposed_placement_decisions"][1]["canonicalization_decision"]["canonical_memory_id"] =
        json!(h(0x10));
    report["proposed_placement_decisions"][1]["canonicalization_decision"]["matched_memory_ids"] =
        json!([h(0x10)]);
    report["proposed_placement_decisions"][1]["canonicalization_decision"]["confidence_bp"] =
        json!(10000);

    let summary = persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("duplicate import");
    assert_eq!(summary.inserted_graph_edge_count, 1);
    assert_eq!(row_count(&db.pool, "dagdb_graph_edges").await, 1);
    assert_eq!(
        scalar_count_where(&db.pool, "dagdb_graph_edges", "edge_kind = 'duplicate_of'").await,
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
    db.cleanup().await;
}

async fn row_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .expect("count table rows")
}

async fn receipt_event_count(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_receipts WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(pool)
        .await
        .expect("count receipt event rows")
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

async fn assert_existing_row_mismatch(
    label: &str,
    update_sql: &'static str,
    id_byte: u8,
    expected_reason_prefix: &str,
) {
    let Some(db) = TestDb::new(label).await else {
        return;
    };
    let report = base_report();
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("first persisted KG import");
    let update = sqlx::query(update_sql)
        .bind(h(id_byte))
        .execute(&db.pool)
        .await
        .expect("mutate existing persisted row");
    assert_eq!(update.rows_affected(), 1);

    let mut new_batch = report;
    new_batch["batch_id"] = json!(h(0xfe));
    let result = persist_kg_import_report(&db.pool, &new_batch.to_string()).await;
    assert!(
        matches!(
            result,
            Err(KgImportPersistenceError::Conflict { ref reason })
                if reason.starts_with(expected_reason_prefix)
        ),
        "existing row mismatch must fail closed for {label}, got {result:?}"
    );
    assert_eq!(row_count(&db.pool, "dagdb_idempotency_keys").await, 1);
    db.cleanup().await;
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
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
            "metadata": {"source": "kg_import_persistence_contract"}
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
            "metadata": {"source": "kg_import_persistence_contract"}
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
            "metadata": {}
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
    report["proposed_placement_decisions"][1]["created_child_layer_id"] =
        json!(layer_id("root/knowledge-graph", 1));
    report["proposed_placement_decisions"][1]["layer_fallback_used"] = json!(false);
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
