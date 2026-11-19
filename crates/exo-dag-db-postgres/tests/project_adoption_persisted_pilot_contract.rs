#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use exo_dag_db_postgres::{
    KG_CONTEXT_PACKET_PREVIEW_SCHEMA, KG_EXPORT_DATABASE_URL_ENV, KG_PORTABLE_EXPORT_SCHEMA,
    KgExportScope, KgRetrievalRequest,
    postgres::{
        DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL, DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_SCHEMA_SQL, kg_export, kg_import::persist_kg_import_report,
        kg_retrieval::retrieve_kg_context_packet,
    },
};
use serde_json::Value as JsonValue;
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Clone, Copy)]
struct PilotCase {
    schema_label: &'static str,
    display_name: &'static str,
    report_path: &'static str,
    tenant_id: &'static str,
    namespace: &'static str,
    safe_graph_root: &'static str,
    source_ref: &'static str,
    expect_absolute_source_root: bool,
}

const THE_TEAM: PilotCase = PilotCase {
    schema_label: "the_team",
    display_name: "The Team",
    report_path: "target/dagdb/project_adoption/the-team/project_memory_v1/report.json",
    tenant_id: "the-team-local",
    namespace: "the-team",
    safe_graph_root: "KnowledgeGraphs/the-team",
    source_ref: "the-team-project_memory_v1",
    expect_absolute_source_root: true,
};

const DAG_DB: PilotCase = PilotCase {
    schema_label: "dag_db",
    display_name: "DAG DB",
    report_path: "target/dagdb/project_adoption/dag_db/project_memory_v3/report.json",
    tenant_id: "dag_db-local",
    namespace: "dag_db",
    safe_graph_root: "KnowledgeGraphs/dag-db",
    source_ref: "dag_db-project_memory_v3",
    expect_absolute_source_root: false,
};

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var(KG_EXPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping project adoption persisted pilot: {KG_EXPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_project_adoption_{label}_{}", std::process::id());
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
async fn project_adoption_persisted_pilot_proves_the_team_repository_test_path() {
    run_persisted_pilot(THE_TEAM).await;
}

#[tokio::test]
async fn project_adoption_persisted_pilot_proves_dag_db_repository_test_path() {
    run_persisted_pilot(DAG_DB).await;
}

async fn run_persisted_pilot(pilot: PilotCase) {
    let Some(db) = TestDb::new(pilot.schema_label).await else {
        return;
    };

    let Some((report_json, expected)) = sanitized_report(pilot) else {
        return;
    };
    assert_no_forbidden_material("sanitized import report", &report_json);

    let import_summary = persist_kg_import_report(&db.pool, &report_json)
        .await
        .unwrap_or_else(|error| panic!("persist {} import report: {error}", pilot.display_name));
    assert_eq!(import_summary.tenant_id, pilot.tenant_id);
    assert_eq!(import_summary.namespace, pilot.namespace);
    assert_eq!(import_summary.inserted_memory_count, expected.memory_count);
    assert_eq!(import_summary.inserted_catalog_count, expected.memory_count);
    assert_eq!(
        import_summary.inserted_graph_node_count,
        expected.memory_count
    );
    assert_eq!(
        import_summary.inserted_graph_edge_count,
        expected.graph_edge_count
    );
    assert_eq!(
        import_summary.inserted_validation_report_count,
        expected.memory_count
    );
    assert_eq!(
        import_summary.inserted_placement_decision_count,
        expected.memory_count
    );
    assert_eq!(
        import_summary.inserted_placement_trace_count,
        expected.memory_count
    );
    assert_eq!(
        import_summary.inserted_receipt_count,
        expected.receipt_count
    );
    assert!(!import_summary.replayed);
    assert_eq!(
        table_count(&db.pool, "dagdb_memory_objects").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_catalog_entries").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_graph_nodes").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_graph_edges").await,
        i64::from(expected.graph_edge_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_validation_reports").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_receipts").await,
        i64::from(expected.receipt_count)
    );
    assert_eq!(import_idempotency_count(&db.pool).await, 1);

    let replay = persist_kg_import_report(&db.pool, &report_json)
        .await
        .unwrap_or_else(|error| panic!("replay {} import report: {error}", pilot.display_name));
    assert!(replay.replayed);
    assert_eq!(replay.inserted_memory_count, expected.memory_count);
    assert_eq!(
        table_count(&db.pool, "dagdb_memory_objects").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_graph_edges").await,
        i64::from(expected.graph_edge_count)
    );
    assert_eq!(import_idempotency_count(&db.pool).await, 1);

    let mut mismatched: JsonValue =
        serde_json::from_str(&report_json).expect("parse sanitized report");
    mismatched["proposed_memory_records"][0]["summary"]["text"] =
        JsonValue::String("Mismatched replay summary".to_owned());
    let mismatched_json = serde_json::to_string(&mismatched).expect("serialize mismatch report");
    assert!(
        persist_kg_import_report(&db.pool, &mismatched_json)
            .await
            .is_err(),
        "same import idempotency key with different request material must fail closed"
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_memory_objects").await,
        i64::from(expected.memory_count)
    );
    assert_eq!(import_idempotency_count(&db.pool).await, 1);

    let preview =
        retrieve_kg_context_packet(&db.pool, &retrieval_request(pilot, expected.memory_count))
            .await
            .unwrap_or_else(|error| {
                panic!("retrieve {} context preview: {error}", pilot.display_name)
            });
    assert_eq!(preview.schema_version, KG_CONTEXT_PACKET_PREVIEW_SCHEMA);
    assert_eq!(preview.tenant_id, pilot.tenant_id);
    assert_eq!(preview.namespace, pilot.namespace);
    assert_eq!(
        preview.memory_refs.len(),
        usize::try_from(expected.memory_count).expect("memory count fits usize")
    );
    assert!(!preview.retrieval_diagnostics.raw_markdown_returned);
    assert!(preview.dry_run_or_preview_only);
    assert!(
        preview
            .memory_refs
            .iter()
            .all(|memory| memory.source_path.is_none())
    );
    assert_no_forbidden_material(
        "retrieval preview",
        &serde_json::to_string(&preview).expect("serialize preview"),
    );

    let export = kg_export::build_kg_portable_export(
        &db.pool,
        &export_scope(pilot),
        std::slice::from_ref(&preview),
    )
    .await
    .unwrap_or_else(|error| panic!("build {} export: {error}", pilot.display_name));
    assert_eq!(export.schema_version, KG_PORTABLE_EXPORT_SCHEMA);
    assert_eq!(export.tenant_id, pilot.tenant_id);
    assert_eq!(export.namespace, pilot.namespace);
    assert_eq!(
        export.memory_records.len(),
        usize::try_from(expected.memory_count).expect("memory count fits usize")
    );
    assert_eq!(
        export.catalog_entries.len(),
        usize::try_from(expected.memory_count).expect("memory count fits usize")
    );
    assert_eq!(
        export.graph_nodes.len(),
        usize::try_from(expected.memory_count).expect("memory count fits usize")
    );
    assert_eq!(
        export.graph_edges.len(),
        usize::try_from(expected.graph_edge_count).expect("edge count fits usize")
    );
    assert_eq!(
        export.validation_reports.len(),
        usize::try_from(expected.memory_count).expect("memory count fits usize")
    );
    assert!(export.diagnostics.raw_material_exclusion_enforced);
    assert!(!export.verification.gateway_api_exposure_implemented);
    assert!(!export.verification.graph_explorer_changes_implemented);
    assert!(!export.verification.production_route_activation_implemented);
    assert!(!export.verification.route_invalidation_writes_implemented);
    assert!(!export.verification.exo_dag_tables_mutated);
    assert_no_forbidden_material(
        "portable export",
        &serde_json::to_string(&export).expect("serialize export"),
    );

    let persisted_export =
        kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
            .await
            .unwrap_or_else(|error| panic!("persist {} export: {error}", pilot.display_name));
    assert_eq!(persisted_export.inserted_export_count, 1);
    assert_eq!(persisted_export.inserted_challenge_count, 5);
    assert_eq!(persisted_export.inserted_receipt_count, 1);
    assert_eq!(persisted_export.inserted_subject_receipt_head_count, 1);
    assert_eq!(persisted_export.inserted_idempotency_response_count, 1);
    assert_eq!(persisted_export.persisted_route_invalidation_count, 0);
    assert_eq!(persisted_export.persisted_dag_outbox_count, 0);
    assert_eq!(persisted_export.persisted_raw_artifact_count, 0);
    assert_eq!(persisted_export.persisted_exo_dag_write_count, 0);
    assert_no_forbidden_material(
        "persisted export summary",
        &serde_json::to_string(&persisted_export).expect("serialize persisted export"),
    );

    let export_replay =
        kg_export::persist_kg_portable_export(&db.pool, &export, "did:exo:exporter")
            .await
            .unwrap_or_else(|error| {
                panic!("replay {} export persistence: {error}", pilot.display_name)
            });
    assert!(export_replay.replayed);
    assert_eq!(table_count(&db.pool, "dagdb_exports").await, 1);
    assert_eq!(table_count(&db.pool, "dagdb_export_challenges").await, 5);
    assert_eq!(export_idempotency_count(&db.pool).await, 1);

    let verification = kg_export::verify_persisted_kg_export(
        &db.pool,
        &export,
        &persisted_export,
        "did:exo:exporter",
    )
    .await
    .expect("verify The Team export persistence");
    assert!(verification.verified);
    assert_eq!(verification.route_invalidation_rows, 0);
    assert_eq!(verification.dagdb_dag_outbox_rows, 0);
    assert_eq!(verification.raw_artifact_rows, 0);
    assert_eq!(verification.exo_dag_rows, 0);
    assert_eq!(route_invalidation_count(&db.pool).await, 0);
    assert_eq!(dag_outbox_count(&db.pool).await, 0);
    assert_eq!(exo_dag_table_count(&db.pool).await, 0);

    db.cleanup().await;
}

/// Persist counts derived from the generated dry-run report so the contract
/// tracks the live KG corpus instead of hardcoded sizes that drift as the
/// corpus grows.
#[derive(Clone, Copy)]
struct ExpectedCounts {
    memory_count: u32,
    graph_edge_count: u32,
    receipt_count: u32,
}

fn count_field(counts: &JsonValue, field: &str, display_name: &str) -> u32 {
    let value = counts
        .get(field)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| {
            panic!("{display_name} report counts.{field} missing or not an integer")
        });
    u32::try_from(value).unwrap_or_else(|_| panic!("{display_name} report counts.{field} overflow"))
}

/// Read and sanitize the dry-run report, returning the sanitized JSON plus the
/// counts derived from it. Returns `None` (with an explicit skip message) when
/// the gitignored report artifact has not been generated, mirroring the
/// env-var skip rather than panicking on developer-specific local state.
fn sanitized_report(pilot: PilotCase) -> Option<(String, ExpectedCounts)> {
    let path = workspace_root().join(pilot.report_path);
    let Ok(raw) = fs::read_to_string(&path) else {
        eprintln!(
            "skipping {} persisted pilot: dry-run report not generated at {}",
            pilot.display_name,
            path.display()
        );
        return None;
    };
    let report: JsonValue = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("parse {} dry-run report: {error}", pilot.display_name));

    if pilot.expect_absolute_source_root {
        let graph_root = report["graph_root"]
            .as_str()
            .expect("external dry-run report graph_root must be a string");
        // OS-independent check: the external artifact's recorded source root is an
        // absolute path (Unix root or Windows drive prefix), without pinning the
        // operator's specific home/OS layout (e.g. "/Users/").
        let is_absolute = graph_root.starts_with('/')
            || graph_root
                .as_bytes()
                .get(1)
                .is_some_and(|byte| *byte == b':');
        assert!(
            is_absolute,
            "external dry-run artifact should retain an absolute source-root provenance before persisted sanitization; got {graph_root:?}"
        );
    }
    assert_eq!(report["tenant_id"], pilot.tenant_id);
    assert_eq!(report["namespace"], pilot.namespace);

    let counts = &report["counts"];
    let memory_count = count_field(counts, "proposed_memory_records", pilot.display_name);
    let expected = ExpectedCounts {
        memory_count,
        graph_edge_count: count_field(counts, "proposed_graph_edges", pilot.display_name),
        // persist consumes one intake + one catalog-approval + one validation
        // receipt per memory record.
        receipt_count: memory_count.saturating_mul(3),
    };

    let mut report = report;
    report["graph_root"] = JsonValue::String(pilot.safe_graph_root.to_owned());
    let sanitized = serde_json::to_string(&report).unwrap_or_else(|error| {
        panic!("serialize sanitized {} report: {error}", pilot.display_name)
    });
    Some((sanitized, expected))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn retrieval_request(pilot: PilotCase, max_memory_refs: u32) -> KgRetrievalRequest {
    KgRetrievalRequest {
        tenant_id: pilot.tenant_id.to_owned(),
        namespace: pilot.namespace.to_owned(),
        task_hash: Some(h(0xa1)),
        task_description: None,
        token_budget: 10_000,
        requested_memory_ids: Vec::new(),
        catalog_path: None,
        max_memory_refs: Some(max_memory_refs),
        layer_path: None,
        max_layer_depth: None,
        max_layers_selected: None,
        max_nodes_per_layer: None,
        max_layer_edges: None,
    }
}

fn export_scope(pilot: PilotCase) -> KgExportScope {
    KgExportScope {
        tenant_id: pilot.tenant_id.to_owned(),
        namespace: pilot.namespace.to_owned(),
        included_memory_ids: Vec::new(),
        included_graph_styles: Vec::new(),
        included_writeback_idempotency_keys: Vec::new(),
        source_commit_or_repo_ref: Some(pilot.source_ref.to_owned()),
        include_preview_context: true,
    }
}

async fn table_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("count {table}: {err}"))
}

async fn import_idempotency_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE route_name = 'dagdb.kg_import.persisted.v1'",
    )
    .fetch_one(pool)
    .await
    .expect("count import idempotency rows")
}

async fn export_idempotency_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE route_name = 'dagdb.kg_export.persisted.v1'",
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
    )
}
