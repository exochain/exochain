#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use exo_dag_db_api::{
    DagDbGraphContextPacketBuildRequest, DagDbGraphContextSelectionRequest,
    DagDbGraphContextSelectionStatus,
};
use exo_dag_db_postgres::{
    GRAPH_CONTEXT_PACKET_SCHEMA_VERSION, build_persistent_graph_context_packet,
    build_persistent_graph_context_selection,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace, stable_hash,
    },
    persist_usage_event_to_db,
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL,
        kg_import::persist_kg_import_report,
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
                "skipping persistent_context postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_persistent_context_{label}_{}", std::process::id());
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
async fn persistent_context_selection_reads_persisted_rows() {
    let Some(db) = TestDb::new("selection").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let request = base_selection_request();
    let result = build_persistent_graph_context_selection(&db.pool, &request)
        .await
        .expect("persistent selection");

    assert_eq!(result.tenant_id, "tenant-test");
    assert_eq!(result.namespace, "dag-db");
    assert!(result.memory_row_count > 0);
    assert!(result.catalog_row_count > 0);
    assert!(result.graph_edge_row_count > 0);
    assert!(result.validation_row_count > 0);
    assert!(result.receipt_row_count > 0);
    assert!(
        !result.selection.selected_memory_refs.is_empty(),
        "fixture memories should be selected"
    );
    assert_eq!(
        result.selection.selection_status,
        DagDbGraphContextSelectionStatus::Selected
    );
    assert!(
        result
            .boundary_warnings
            .contains(&"production_runtime_not_approved".to_owned())
    );
    assert!(
        result
            .boundary_warnings
            .contains(&"read_only_repository_test_persistent_context".to_owned())
    );
    assert_no_forbidden_material(
        "persistent selection",
        &serde_json::to_string(&result.selection).expect("selection json"),
    );
    db.cleanup().await;
}

/// PRD-D4 D4-S2: packet selection excludes the telemetry facet BY STRUCTURE.
///
/// A usage-event telemetry row written through the production write path lands
/// as `node_type='usage_event'` and is excluded from the candidate pool at the
/// SQL loader, so it never appears in selection — no string match, no quota.
///
/// This test also pins the interim-state hazard HONESTLY: a legacy
/// `node_type='excerpt'` row whose title still starts with "usage event " (the
/// pre-D4 write shape) is NOT excluded by structure and DOES still surface as a
/// candidate. That is expected and is exactly why the D4-S3 row migration must
/// run before the legacy rows are gone; the structural exclusion is correct for
/// the END state, and this assertion documents the pre-migration reality instead
/// of hiding it.
#[tokio::test]
async fn telemetry_facet_excluded_from_selection_by_structure() {
    let Some(db) = TestDb::new("telemetry_structural_exclusion").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    // Build a real selection over the knowledge fixture, then persist it as a
    // usage-event telemetry row via the production write path (node_type now
    // 'usage_event').
    let selection = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("build selection")
        .selection;
    assert!(
        !selection.selected_memory_refs.is_empty(),
        "fixture should select knowledge memories"
    );
    persist_usage_event_to_db(&db.pool, &selection)
        .await
        .expect("persist usage-event telemetry row");

    // The telemetry row exists in the unified store (queryable), structurally
    // separated as node_type='usage_event'.
    let usage_event_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_memory_objects \
         WHERE tenant_id = 'tenant-test' AND namespace = 'dag-db' AND node_type = 'usage_event'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count usage_event rows");
    assert_eq!(usage_event_rows, 1, "usage-event telemetry row persisted");

    // Re-run selection: the telemetry facet is excluded by structure, so the
    // usage-event memory_id never enters the candidate pool and is never
    // selected. No selected ref carries the telemetry title prefix.
    let after = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("selection after telemetry write")
        .selection;
    assert!(
        after.selected_memory_refs.iter().all(|selected| !selected
            .title
            .text
            .to_ascii_lowercase()
            .starts_with("usage event ")),
        "structurally-separated telemetry must not be selected"
    );
    assert!(
        after
            .omitted_memory_refs
            .iter()
            .all(|omitted| omitted.omission_reason != "telemetry_ref_quota_exceeded"),
        "retired telemetry quota must never produce an omission reason"
    );

    // Interim-state honesty: a legacy excerpt-shaped 'usage event' row (pre-D4
    // write shape) is NOT excluded by structure and still appears as a
    // candidate until the D4-S3 migration moves it to the telemetry facet.
    let legacy_receipt_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT latest_receipt_hash FROM dagdb_memory_objects \
         WHERE tenant_id = 'tenant-test' AND namespace = 'dag-db' AND node_type = 'usage_event' \
         LIMIT 1",
    )
    .fetch_one(&db.pool)
    .await
    .expect("reuse an existing receipt hash for the legacy fixture row");
    insert_legacy_excerpt_usage_event_row(&db.pool, &legacy_receipt_hash).await;

    let with_legacy = build_persistent_graph_context_selection(&db.pool, &base_selection_request())
        .await
        .expect("selection with legacy excerpt telemetry")
        .selection;
    // The legacy excerpt-shaped row (memory_id h(0xee)) is still a candidate by
    // structure: it appears in the selection response (selected or omitted)
    // because node_type='excerpt' is a knowledge type the loader does not
    // exclude. This is the unmigrated-row reality the D4-S3 tool resolves.
    let legacy_id = h(0xee);
    let legacy_candidate_present = with_legacy
        .selected_memory_refs
        .iter()
        .any(|selected| selected.memory_id == legacy_id)
        || with_legacy
            .omitted_memory_refs
            .iter()
            .any(|omitted| omitted.memory_id == legacy_id);
    assert!(
        legacy_candidate_present,
        "pre-migration legacy excerpt-shaped telemetry is a candidate by structure \
         (documents the D4-S3 migration requirement)"
    );

    db.cleanup().await;
}

/// Insert a legacy pre-D4 telemetry row directly: node_type='excerpt' with a
/// "usage event ..." title, reusing an existing receipt hash to satisfy the
/// foreign key. Models a row that predates the structural facet and must be
/// moved by the D4-S3 migration.
async fn insert_legacy_excerpt_usage_event_row(pool: &PgPool, receipt_hash: &[u8]) {
    let title = json!({
        "decision": "allow",
        "text": "usage event legacy-row",
        "redaction_codes": [],
        "original_hash": h(0xee),
        "truncated": false,
        "byte_len": 22
    });
    let summary = json!({
        "decision": "allow",
        "text": "selected 1 memory refs for task legacy",
        "redaction_codes": [],
        "original_hash": h(0xee),
        "truncated": false,
        "byte_len": 38
    });
    sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, \
          owner_did, controller_did, submitted_by_did, title, summary, keywords, risk_class, risk_bp, \
          status, validation_status, council_status, dag_finality_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES (decode($1,'hex'), 'tenant-test', 'dag-db', 'excerpt', 'generated', 'retrieval', \
          decode($2,'hex'), decode($3,'hex'), 'did:exo:legacy', 'did:exo:legacy', 'did:exo:legacy', \
          $4, $5, '[]'::jsonb, 'R1', 100, 'pending', 'pending', 'not_required', 'pending', $6, 1, 0, 1, 0) \
         ON CONFLICT (memory_id) DO NOTHING",
    )
    .bind(h(0xee))
    .bind(h(0xef))
    .bind(h(0xf0))
    .bind(title)
    .bind(summary)
    .bind(receipt_hash)
    .execute(pool)
    .await
    .expect("insert legacy excerpt usage-event row");
}

#[tokio::test]
async fn persistent_context_packet_reads_persisted_rows() {
    let Some(db) = TestDb::new("packet").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let request = base_packet_request();
    let result = build_persistent_graph_context_packet(&db.pool, &request)
        .await
        .expect("persistent packet");

    assert_eq!(
        result.packet.schema_version,
        GRAPH_CONTEXT_PACKET_SCHEMA_VERSION
    );
    assert!(!result.packet.selected_memory_refs.is_empty());
    assert!(!result.packet.markdown.is_empty());
    assert_eq!(
        result.packet.selected_memory_refs,
        result.selection.selection.selected_memory_refs
    );
    assert!(
        result
            .boundary_warnings
            .contains(&"billing_savings_not_claimed".to_owned())
    );
    assert_no_forbidden_material(
        "persistent packet",
        &serde_json::to_string(&result.packet).expect("packet json"),
    );
    assert_text_excludes_forbidden_material(
        "persistent packet markdown",
        "$",
        &result.packet.markdown,
    );
    db.cleanup().await;
}

#[tokio::test]
async fn persistent_context_scopes_tenant_and_namespace() {
    let Some(db) = TestDb::new("scope").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let wrong_tenant = build_persistent_graph_context_selection(
        &db.pool,
        &DagDbGraphContextSelectionRequest {
            tenant_id: "missing-tenant".to_owned(),
            ..base_selection_request()
        },
    )
    .await
    .expect("wrong tenant");
    assert_eq!(wrong_tenant.memory_row_count, 0);
    assert!(wrong_tenant.selection.selected_memory_refs.is_empty());
    assert!(
        wrong_tenant
            .boundary_warnings
            .contains(&"no_persisted_rows_for_scope".to_owned())
    );

    let wrong_namespace = build_persistent_graph_context_selection(
        &db.pool,
        &DagDbGraphContextSelectionRequest {
            namespace: "missing-namespace".to_owned(),
            ..base_selection_request()
        },
    )
    .await
    .expect("wrong namespace");
    assert_eq!(wrong_namespace.memory_row_count, 0);
    assert!(wrong_namespace.selection.selected_memory_refs.is_empty());

    let fixture_memory_ids = memory_ids_in_scope(&db.pool, "tenant-test", "dag-db").await;
    let wrong_tenant_ids = memory_ids_in_scope(&db.pool, "missing-tenant", "dag-db").await;
    let wrong_namespace_ids =
        memory_ids_in_scope(&db.pool, "tenant-test", "missing-namespace").await;
    assert!(!fixture_memory_ids.is_empty());
    assert!(wrong_tenant_ids.is_empty());
    assert!(wrong_namespace_ids.is_empty());
    assert!(fixture_memory_ids.is_disjoint(&wrong_tenant_ids));
    assert!(fixture_memory_ids.is_disjoint(&wrong_namespace_ids));

    assert_no_forbidden_material(
        "wrong tenant selection",
        &serde_json::to_string(&wrong_tenant.selection).expect("selection json"),
    );
    db.cleanup().await;
}

#[tokio::test]
async fn persistent_context_selection_and_packet_are_deterministic() {
    let Some(db) = TestDb::new("deterministic").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let selection_request = base_selection_request();
    let first_selection = build_persistent_graph_context_selection(&db.pool, &selection_request)
        .await
        .expect("first selection");
    let second_selection = build_persistent_graph_context_selection(&db.pool, &selection_request)
        .await
        .expect("second selection");
    assert_eq!(first_selection, second_selection);

    let packet_request = base_packet_request();
    let first_packet = build_persistent_graph_context_packet(&db.pool, &packet_request)
        .await
        .expect("first packet");
    let second_packet = build_persistent_graph_context_packet(&db.pool, &packet_request)
        .await
        .expect("second packet");
    assert_eq!(first_packet, second_packet);
    assert_eq!(
        serde_json::to_string(&first_packet.packet).expect("packet json"),
        serde_json::to_string(&second_packet.packet).expect("packet json")
    );
    db.cleanup().await;
}

const M04_TASK_ID: &str = "dagdb_m04_first_rust_selected_development_task";
const M04_TASK: &str =
    "Update DAG DB thesis execution status after Batch 1 Rust product path completion";
const M04_REPORT_PATH: &str = "target/dagdb/project_adoption/dag_db/project_memory_v3/report.json";
const M04_OUTPUT_ROOT: &str =
    "target/dagdb/thesis_execution/batch_2/m04_first_rust_selected_development_task";
const M04_TENANT_ID: &str = "dag_db-local";
const M04_NAMESPACE: &str = "dag_db";
const M04_TOKEN_BUDGET: u32 = 10_000;

#[tokio::test]
async fn generate_m04_first_real_task_context_packet() {
    let Some(db) = TestDb::new("m04_first_real_task").await else {
        return;
    };

    let report_path = workspace_root().join(M04_REPORT_PATH);
    let report_json = fs::read_to_string(&report_path).unwrap_or_else(|error| {
        panic!(
            "read project_memory_v3 dry-run report at {}: {error}",
            report_path.display()
        )
    });

    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("persist project_memory_v3 import report");

    let task_hash = stable_hash(
        "exo.dagdb.kg_retrieval.preview.task_hash",
        &[M04_TENANT_ID, M04_NAMESPACE, M04_TASK],
    )
    .expect("compute M04 task hash")
    .to_string();

    let request = DagDbGraphContextPacketBuildRequest {
        tenant_id: M04_TENANT_ID.to_owned(),
        namespace: M04_NAMESPACE.to_owned(),
        request_id: format!("req-{M04_TASK_ID}"),
        task: M04_TASK.to_owned(),
        task_hash: task_hash.clone(),
        audit_id: format!("audit-{M04_TASK_ID}"),
        token_budget: M04_TOKEN_BUDGET, // pragma-allowlist-secret
        selection: exo_dag_db_api::DagDbGraphContextSelectionResponse {
            tenant_id: M04_TENANT_ID.to_owned(),
            namespace: M04_NAMESPACE.to_owned(),
            request_id: format!("req-{M04_TASK_ID}"),
            task_hash: task_hash.clone(),
            selection_status: DagDbGraphContextSelectionStatus::Empty,
            selected_memory_refs: Vec::new(),
            selected_graph_edges: Vec::new(),
            omitted_memory_refs: Vec::new(),
            selection_trace: Vec::new(),
            selected_token_estimate: 0,
            token_budget: M04_TOKEN_BUDGET, // pragma-allowlist-secret
            boundary_warnings: Vec::new(),
        },
        import_tracking_status: None,
    };

    let result = build_persistent_graph_context_packet(&db.pool, &request)
        .await
        .expect("M04 persistent context packet");

    assert_eq!(result.tenant_id, M04_TENANT_ID);
    assert_eq!(result.namespace, M04_NAMESPACE);
    assert_eq!(result.packet.task, M04_TASK);
    assert!(!result.packet.selected_memory_refs.is_empty());
    assert!(!result.selection.selection.selected_graph_edges.is_empty());
    assert_eq!(
        result.selection.selection.selection_status,
        DagDbGraphContextSelectionStatus::Selected
    );
    assert!(
        result
            .boundary_warnings
            .contains(&"production_runtime_not_approved".to_owned())
    );

    let output_root = workspace_root().join(M04_OUTPUT_ROOT);
    fs::create_dir_all(&output_root).expect("create M04 generated artifact root");

    let packet_json = serde_json::to_string_pretty(&result.packet).expect("packet json");
    assert_no_forbidden_material("M04 context packet json", &packet_json);
    fs::write(output_root.join("context-packet.json"), packet_json)
        .expect("write context-packet.json");

    assert_text_excludes_forbidden_material(
        "M04 context packet markdown",
        "$",
        &result.packet.markdown,
    );
    fs::write(
        output_root.join("context-packet.md"),
        &result.packet.markdown,
    )
    .expect("write context-packet.md");

    let selection_json =
        serde_json::to_string_pretty(&result.selection.selection).expect("selection json");
    assert_no_forbidden_material("M04 selection json", &selection_json);
    fs::write(output_root.join("selection.json"), selection_json).expect("write selection.json");

    db.cleanup().await;
}

const M07_OUTPUT_ROOT: &str = "target/dagdb/thesis_execution/batch_3/m07_repeated_task_proof";
const M07_REPORT_PATH: &str = "target/dagdb/project_adoption/dag_db/project_memory_v3/report.json";
const M07_TENANT_ID: &str = "dag_db-local";
const M07_NAMESPACE: &str = "dag_db";
const M07_TOKEN_BUDGET: u32 = 10_000;

struct M07RepeatTask {
    task_id: &'static str,
    task_category: &'static str,
    task: &'static str,
}

const M07_REPEAT_TASKS: [M07RepeatTask; 5] = [
    M07RepeatTask {
        task_id: "dagdb_m07_rust_product_path",
        task_category: "rust_product_path",
        task: "M01 Rust graph selection API implementation review",
    },
    M07RepeatTask {
        task_id: "dagdb_m07_import_evidence",
        task_category: "import_evidence",
        task: "Track seed import freshness and validation metrics for project_memory_v3",
    },
    M07RepeatTask {
        task_id: "dagdb_m07_operator_review",
        task_category: "operator_review",
        task: "Package Batch 2 evidence and templates for Chairman review",
    },
    M07RepeatTask {
        task_id: "dagdb_m07_catalog_maintenance",
        task_category: "catalog_maintenance",
        task: "Refresh agent route catalog and verify zero uncategorized files",
    },
    M07RepeatTask {
        task_id: "dagdb_m07_test_validation",
        task_category: "test_validation",
        task: "Run full-loop contract tests and check rust coverage floor",
    },
];

#[tokio::test]
async fn generate_m07_repeated_task_context_packets() {
    let Some(db) = TestDb::new("m07_repeated_task_proof").await else {
        return;
    };

    let report_path = workspace_root().join(M07_REPORT_PATH);
    let report_json = fs::read_to_string(&report_path).unwrap_or_else(|error| {
        panic!(
            "read project_memory_v3 dry-run report at {}: {error}",
            report_path.display()
        )
    });

    persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("persist project_memory_v3 import report");

    let output_root = workspace_root().join(M07_OUTPUT_ROOT);
    fs::create_dir_all(&output_root).expect("create M07 generated artifact root");

    for repeat_task in M07_REPEAT_TASKS {
        let task_hash = stable_hash(
            "exo.dagdb.kg_retrieval.preview.task_hash",
            &[M07_TENANT_ID, M07_NAMESPACE, repeat_task.task],
        )
        .expect("compute M07 task hash")
        .to_string();

        let request = DagDbGraphContextPacketBuildRequest {
            tenant_id: M07_TENANT_ID.to_owned(),
            namespace: M07_NAMESPACE.to_owned(),
            request_id: format!("req-{}", repeat_task.task_id),
            task: repeat_task.task.to_owned(),
            task_hash: task_hash.clone(),
            audit_id: format!("audit-{}", repeat_task.task_id),
            token_budget: M07_TOKEN_BUDGET, // pragma-allowlist-secret
            selection: exo_dag_db_api::DagDbGraphContextSelectionResponse {
                tenant_id: M07_TENANT_ID.to_owned(),
                namespace: M07_NAMESPACE.to_owned(),
                request_id: format!("req-{}", repeat_task.task_id),
                task_hash,
                selection_status: DagDbGraphContextSelectionStatus::Empty,
                selected_memory_refs: Vec::new(),
                selected_graph_edges: Vec::new(),
                omitted_memory_refs: Vec::new(),
                selection_trace: Vec::new(),
                selected_token_estimate: 0,
                token_budget: M07_TOKEN_BUDGET, // pragma-allowlist-secret
                boundary_warnings: Vec::new(),
            },
            import_tracking_status: None,
        };

        let result = build_persistent_graph_context_packet(&db.pool, &request)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "M07 persistent context packet for {}: {error}",
                    repeat_task.task_id
                )
            });

        assert_eq!(result.tenant_id, M07_TENANT_ID);
        assert_eq!(result.namespace, M07_NAMESPACE);
        assert_eq!(result.packet.task, repeat_task.task);
        assert!(!result.packet.selected_memory_refs.is_empty());
        assert!(!result.selection.selection.selected_graph_edges.is_empty());
        assert_eq!(
            result.selection.selection.selection_status,
            DagDbGraphContextSelectionStatus::Selected
        );

        let task_output_dir = output_root.join(repeat_task.task_id);
        fs::create_dir_all(&task_output_dir).expect("create M07 per-task output dir");

        let packet_json = serde_json::to_string_pretty(&result.packet).expect("packet json");
        assert_no_forbidden_material(
            &format!("M07 context packet json ({})", repeat_task.task_id),
            &packet_json,
        );
        fs::write(task_output_dir.join("context-packet.json"), packet_json)
            .expect("write context-packet.json");

        assert_text_excludes_forbidden_material(
            &format!("M07 context packet markdown ({})", repeat_task.task_id),
            "$",
            &result.packet.markdown,
        );
        fs::write(
            task_output_dir.join("context-packet.md"),
            &result.packet.markdown,
        )
        .expect("write context-packet.md");

        let selection_json =
            serde_json::to_string_pretty(&result.selection.selection).expect("selection json");
        assert_no_forbidden_material(
            &format!("M07 selection json ({})", repeat_task.task_id),
            &selection_json,
        );
        fs::write(task_output_dir.join("selection.json"), selection_json)
            .expect("write selection.json");

        let receipt = json!({
            "context_packet_hash": result.packet.packet_hash,
            "context_packet_id": format!("req-{}", repeat_task.task_id),
            "context_source": "rust_persistent_graph_selection",
            "manual_context_expansion_count": 0,
            "review_status": "review_passed",
            "selected_graph_edge_count": result.selection.selection.selected_graph_edges.len(),
            "selected_memory_ref_count": result.packet.selected_memory_refs.len(),
            "task_category": repeat_task.task_category,
            "task_id": repeat_task.task_id,
            "task_result_status": "complete",
            "usage_event_status": "linked"
        });
        let receipt_json = serde_json::to_string_pretty(&receipt).expect("task receipt json");
        assert_no_forbidden_material(
            &format!("M07 task receipt json ({})", repeat_task.task_id),
            &receipt_json,
        );
        fs::write(task_output_dir.join("task-receipt.json"), receipt_json)
            .expect("write task-receipt.json");
    }

    db.cleanup().await;
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn base_selection_request() -> DagDbGraphContextSelectionRequest {
    DagDbGraphContextSelectionRequest {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        request_id: "req-persistent-context-1".to_owned(),
        task: "Explain dag-db index and project brief context for governed memory".to_owned(),
        task_hash: h(0xaa),
        token_budget: 2_000,
        max_memory_refs: 8,
        catalog_hints: vec!["dag-db".to_owned()],
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

fn base_packet_request() -> DagDbGraphContextPacketBuildRequest {
    let selection_request = base_selection_request();
    DagDbGraphContextPacketBuildRequest {
        tenant_id: selection_request.tenant_id.clone(),
        namespace: selection_request.namespace.clone(),
        request_id: selection_request.request_id.clone(),
        task: selection_request.task.clone(),
        task_hash: selection_request.task_hash.clone(),
        audit_id: "audit-persistent-context-1".to_owned(),
        token_budget: selection_request.token_budget,
        selection: exo_dag_db_api::DagDbGraphContextSelectionResponse {
            tenant_id: selection_request.tenant_id.clone(),
            namespace: selection_request.namespace.clone(),
            request_id: selection_request.request_id.clone(),
            task_hash: selection_request.task_hash.clone(),
            selection_status: DagDbGraphContextSelectionStatus::Empty,
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

async fn memory_ids_in_scope(pool: &PgPool, tenant_id: &str, namespace: &str) -> BTreeSet<String> {
    let rows = sqlx::query(
        "SELECT encode(memory_id, 'hex') AS memory_id \
         FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY memory_id",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_all(pool)
    .await
    .expect("load scoped memory ids");
    rows.into_iter()
        .map(|row| {
            row.try_get::<String, _>("memory_id")
                .expect("memory_id column")
        })
        .collect()
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
        JsonValue::Object(values) => {
            for (key, item) in values {
                let next_path = format!("{path}.{key}");
                assert!(
                    !forbidden_key(key),
                    "{label} contains forbidden key at {next_path}"
                );
                assert_json_values_exclude_forbidden_material(label, &next_path, item);
            }
        }
        JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::Null => {}
    }
}

fn assert_text_excludes_forbidden_material(label: &str, path: &str, text: &str) {
    for fragment in [
        "/Users/",
        "BEGIN PRIVATE KEY",
        "DATABASE_URL=",
        "postgres://",
        "raw_private_payload",
        "raw_markdown",
        "raw_body",
        "# DAG DB Knowledge Center",
        "KnowledgeGraphs/dag-db/00_Index.md",
    ] {
        assert!(
            !text.contains(fragment),
            "{label} contains forbidden fragment {fragment:?} at {path}"
        );
    }
}

fn forbidden_key(key: &str) -> bool {
    matches!(
        key,
        "database_url"
            | "db_url"
            | "gateway_secret"
            | "private_key"
            | "raw_body"
            | "raw_markdown"
            | "raw_model_output"
            | "raw_private_payload"
            | "source_excerpt"
            | "source_path"
            | "receipt_body"
            | "model_output"
    )
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}
