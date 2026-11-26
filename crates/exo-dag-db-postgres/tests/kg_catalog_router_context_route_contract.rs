#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use exo_dag_db_postgres::{
    KG_CATALOG_ROUTER_PREVIEW_SCHEMA, KG_RETRIEVAL_DATABASE_URL_ENV, KgCatalogRouterTaskInput,
    kg_import::{KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DRY_RUN_REPORT_SCHEMA, required_trace},
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        kg_catalog_router::build_kg_catalog_router_preview, kg_import::persist_kg_import_report,
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
        let Ok(database_url) = std::env::var(KG_RETRIEVAL_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping kg_catalog_router postgres test: {KG_RETRIEVAL_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_kg_catalog_router_{label}_{}", std::process::id());
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
async fn kg_catalog_router_deterministic_route_preview() {
    let Some(db) = TestDb::new("deterministic").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let request = base_task(2_000, 5, &[]);
    let first = build_kg_catalog_router_preview(&db.pool, &request)
        .await
        .expect("build catalog route preview");
    let second = build_kg_catalog_router_preview(&db.pool, &request)
        .await
        .expect("build catalog route preview again");

    assert_eq!(first, second, "catalog route preview must be deterministic");
    assert_eq!(first.schema_version, KG_CATALOG_ROUTER_PREVIEW_SCHEMA);
    assert_eq!(
        first.selected_catalog_route.selected_path,
        "KnowledgeGraphs/dag-db/catalog-governed-memory"
    );
    assert_eq!(first.selected_memory_refs.len(), 2);
    assert_eq!(first.selected_graph_edges.len(), 1);
    assert_eq!(first.packet_metrics.selected_ref_count, 2);
    assert_eq!(first.packet_metrics.selected_edge_count, 1);
    assert!(first.packet_metrics.token_estimate <= first.packet_metrics.token_budget);
    assert_eq!(first.packet_metrics.citation_coverage_bp, 10_000);
    assert_eq!(first.packet_metrics.validation_coverage_bp, 10_000);
    assert!(first.catalog_path_candidates.windows(2).all(|window| {
        window[0].route_score_bp > window[1].route_score_bp
            || (window[0].route_score_bp == window[1].route_score_bp
                && window[0].warning_count <= window[1].warning_count)
    }));
    assert!(
        first
            .warnings
            .contains(&"route_activation_not_approved".to_owned())
    );
    assert!(
        first
            .warnings
            .contains(&"route_invalidation_writes_not_approved".to_owned())
    );
    first.validate().expect("valid router preview");
    assert_no_forbidden_material(
        "catalog route preview",
        &first.to_canonical_json().expect("canonical json"),
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_catalog_router_scopes_tenant_namespace() {
    let Some(db) = TestDb::new("scope").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let wrong_tenant = build_kg_catalog_router_preview(
        &db.pool,
        &KgCatalogRouterTaskInput {
            tenant_id: "missing-tenant".to_owned(),
            ..base_task(2_000, 5, &[])
        },
    )
    .await
    .expect("wrong tenant returns empty preview");

    assert!(wrong_tenant.catalog_path_candidates.is_empty());
    assert!(wrong_tenant.selected_memory_refs.is_empty());
    assert!(wrong_tenant.selected_graph_edges.is_empty());
    assert!(
        wrong_tenant
            .warnings
            .contains(&"no_catalog_route_candidates".to_owned())
    );
    assert_no_forbidden_material(
        "wrong tenant preview",
        &wrong_tenant.to_canonical_json().expect("canonical json"),
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_catalog_router_enforces_caps() {
    let Some(db) = TestDb::new("caps").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let max_ref_limited = build_kg_catalog_router_preview(&db.pool, &base_task(2_000, 1, &[]))
        .await
        .expect("max-ref limited preview");
    assert_eq!(max_ref_limited.selected_memory_refs.len(), 1);
    assert!(
        max_ref_limited
            .omitted_refs
            .iter()
            .any(|memory| memory.omission_reason == "max_memory_refs_exceeded")
    );
    assert!(
        max_ref_limited
            .warnings
            .contains(&"context_truncated_by_max_memory_refs".to_owned())
    );

    let token_limited = build_kg_catalog_router_preview(&db.pool, &base_task(1, 5, &[]))
        .await
        .expect("token limited preview");
    assert!(token_limited.selected_memory_refs.is_empty());
    assert!(
        token_limited
            .omitted_refs
            .iter()
            .any(|memory| memory.omission_reason == "token_budget_exceeded")
    );
    assert!(
        token_limited
            .warnings
            .contains(&"context_truncated_by_token_budget".to_owned())
    );
    db.cleanup().await;
}

#[tokio::test]
async fn kg_catalog_router_excludes_raw_material() {
    let Some(db) = TestDb::new("raw_material").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");

    let preview = build_kg_catalog_router_preview(&db.pool, &base_task(2_000, 5, &[]))
        .await
        .expect("build catalog route preview");
    let serialized = preview.to_canonical_json().expect("canonical json");
    assert_no_forbidden_material("catalog route preview", &serialized);
    assert!(!serialized.contains("source_path"));
    assert!(!serialized.contains("receipt_body"));
    assert!(!serialized.contains("model_output"));
    db.cleanup().await;
}

#[tokio::test]
async fn kg_catalog_router_does_not_mutate_route_outbox_or_exo_dag_tables() {
    let Some(db) = TestDb::new("no_mutation").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &base_report().to_string())
        .await
        .expect("persist import fixture");
    let before_route_invalidations = table_count(&db.pool, "dagdb_graph_route_invalidations").await;
    let before_outbox = table_count(&db.pool, "dagdb_dag_outbox").await;
    let before_exo_dag = exo_dag_table_count(&db.pool).await;

    let preview = build_kg_catalog_router_preview(&db.pool, &base_task(2_000, 5, &[]))
        .await
        .expect("build catalog route preview");
    assert_eq!(preview.selected_memory_refs.len(), 2);

    assert_eq!(
        table_count(&db.pool, "dagdb_graph_route_invalidations").await,
        before_route_invalidations
    );
    assert_eq!(
        table_count(&db.pool, "dagdb_dag_outbox").await,
        before_outbox
    );
    assert_eq!(exo_dag_table_count(&db.pool).await, before_exo_dag);
    db.cleanup().await;
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn base_task(
    token_budget: u32,
    max_memory_refs: u32,
    requested: &[String],
) -> KgCatalogRouterTaskInput {
    KgCatalogRouterTaskInput {
        tenant_id: "tenant-test".to_owned(),
        namespace: "dag-db".to_owned(),
        task_description: "Explain catalog governed memory route diagnostics".to_owned(),
        task_hash: h(0xaa),
        requesting_actor_did: Some("did:exo:operator".to_owned()),
        requesting_agent_id: Some("codex-local".to_owned()),
        token_budget,
        max_memory_refs,
        catalog_hints: text_set(&["KnowledgeGraphs/dag-db/catalog-governed-memory"]),
        requested_memory_refs: requested.iter().cloned().collect(),
        risk_boundary_flags: text_set(&["repository_test_only"]),
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
            memory(0x10, 0x20, "KnowledgeGraphs/dag-db/catalog-governed-memory/00.md", "Catalog Router Contract", "catalog governed memory route diagnostics"),
            memory(0x11, 0x21, "KnowledgeGraphs/dag-db/catalog-governed-memory/01.md", "Catalog Route Report", "route report evidence"),
            memory(0x12, 0x22, "KnowledgeGraphs/dag-db/project-adoption/active.md", "Active Memory Set", "project adoption evidence")
        ],
        "proposed_catalog_entries": [
            catalog(0x30, 0x10, 0x20, "Catalog Router Contract"),
            catalog(0x31, 0x11, 0x21, "Catalog Route Report"),
            catalog(0x32, 0x12, 0x22, "Active Memory Set")
        ],
        "proposed_graph_nodes": [
            graph_node(0x40, 0x10, ["KnowledgeGraphs", "dag-db", "catalog-governed-memory"]),
            graph_node(0x41, 0x11, ["KnowledgeGraphs", "dag-db", "catalog-governed-memory"]),
            graph_node(0x42, 0x12, ["KnowledgeGraphs", "dag-db", "project-adoption"])
        ],
        "proposed_graph_edges": [
            graph_edge(0x50, 0x10, 0x11, "related_to"),
            graph_edge(0x51, 0x11, 0x12, "supports")
        ],
        "proposed_required_edges": [
            required_edge(0x50, 0x10, 0x11, "related_to"),
            required_edge(0x51, 0x11, 0x12, "supports")
        ],
        "proposed_placement_decisions": [
            placement(0x60, 0x10, 0xa0),
            placement(0x61, 0x11, 0xa1),
            placement(0x62, 0x12, 0xa2)
        ],
        "proposed_receipt_intents": [
            receipt(0x80, "memory", 0x10, "intake_created"),
            receipt(0x81, "memory", 0x11, "intake_created"),
            receipt(0x82, "memory", 0x12, "intake_created"),
            receipt(0x83, "catalog", 0x30, "memory_approved"),
            receipt(0x84, "catalog", 0x31, "memory_approved"),
            receipt(0x85, "catalog", 0x32, "memory_approved"),
            receipt(0x86, "validation_report", 0x70, "validation_created"),
            receipt(0x87, "validation_report", 0x71, "validation_created"),
            receipt(0x88, "validation_report", 0x72, "validation_created"),
            receipt(0x91, "memory", 0x50, "validation_created"),
            receipt(0x92, "memory", 0x51, "validation_created")
        ],
        "proposed_validation_reports": [
            validation_report(0x70, 0x10),
            validation_report(0x71, 0x11),
            validation_report(0x72, 0x12)
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

fn memory(id: u8, source: u8, path: &str, title: &str, summary: &str) -> JsonValue {
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
        "summary": safe(summary),
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

fn graph_node(id: u8, memory_id: u8, catalog_path: [&str; 3]) -> JsonValue {
    json!({
        "graph_node_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "node_kind": "canonical",
        "catalog_path": catalog_path
    })
}

fn graph_edge(id: u8, from: u8, to: u8, edge_kind: &str) -> JsonValue {
    json!({
        "graph_edge_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "from_memory_id": h(from),
        "to_memory_id": h(to),
        "edge_kind": edge_kind,
        "source_edge_kind": "wikilink",
        "receipt_intent_id": h(id + 0x40)
    })
}

fn required_edge(id: u8, from: u8, to: u8, edge_kind: &str) -> JsonValue {
    json!({
        "required_edge_id": h(id),
        "tenant_id": "tenant-test",
        "namespace": "dag-db",
        "graph_style": "semantic_catalog_graph",
        "from_memory_id": h(from),
        "to_memory_id": h(to),
        "edge_kind": edge_kind,
        "status": "proposed"
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

fn text_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

async fn table_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("count {table}: {err}"))
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
        "# DAG DB Knowledge Center",
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
