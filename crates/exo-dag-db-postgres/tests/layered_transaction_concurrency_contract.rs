#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::Hash256;
use exo_dag_db_api::MemoryGraphStyle;
use exo_dag_db_postgres::{
    deterministic_layer_edge_id, deterministic_layer_id, deterministic_layer_membership_id,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace,
    },
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        kg_import::{KgImportPersistenceError, persist_kg_import_report},
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
        let Ok(database_url) = std::env::var(KG_IMPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping layered transaction concurrency test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_layered_tx_{label}_{}", std::process::id());
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
            .max_connections(4)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TopologyCounts {
    memory_objects: i64,
    catalog_entries: i64,
    graph_nodes: i64,
    graph_edges: i64,
    graph_layers: i64,
    layer_memberships: i64,
    layer_edges: i64,
    placement_decisions: i64,
    placement_traces: i64,
    receipts: i64,
    idempotency_keys: i64,
}

impl TopologyCounts {
    const fn zero() -> Self {
        Self {
            memory_objects: 0,
            catalog_entries: 0,
            graph_nodes: 0,
            graph_edges: 0,
            graph_layers: 0,
            layer_memberships: 0,
            layer_edges: 0,
            placement_decisions: 0,
            placement_traces: 0,
            receipts: 0,
            idempotency_keys: 0,
        }
    }

    const fn persisted_once() -> Self {
        Self {
            memory_objects: 2,
            catalog_entries: 2,
            graph_nodes: 2,
            graph_edges: 1,
            graph_layers: 2,
            layer_memberships: 2,
            layer_edges: 1,
            placement_decisions: 2,
            placement_traces: 2,
            receipts: 6,
            idempotency_keys: 1,
        }
    }
}

#[tokio::test]
async fn layered_import_replay_preserves_topology_counts() {
    let Some(db) = TestDb::new("replay_topology").await else {
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
    assert_topology_counts(&db.pool, TopologyCounts::persisted_once()).await;

    let second = persist_kg_import_report(&db.pool, &report_json)
        .await
        .expect("layered KG import replay");
    assert!(second.replayed);
    assert_topology_counts(&db.pool, TopologyCounts::persisted_once()).await;

    db.cleanup().await;
}

#[tokio::test]
async fn duplicate_layer_path_conflict_is_deterministic_under_concurrent_attempts() {
    let Some(db) = TestDb::new("duplicate_layer_path").await else {
        return;
    };
    let report = layered_report();
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("baseline layered KG import");

    // Layer ids are now bound to the deterministic tenant-scoped derivation,
    // so a different id for the same path is rejected at validation. The
    // persistence conflict is exercised by re-importing the same derived
    // layer id with conflicting row content instead.
    let mut duplicate_path = report;
    duplicate_path["batch_id"] = json!(h(0xd1));
    duplicate_path["proposed_layers"][1]["root_memory_id"] = json!(h(0x10));
    let duplicate_path_json = duplicate_path.to_string();
    let expected_reason = format!(
        "existing dagdb_graph_layers row mismatch for {}",
        layer_id("root/knowledge-graph", 1)
    );

    let left_pool = db.pool.clone();
    let right_pool = db.pool.clone();
    let left_json = duplicate_path_json.clone();
    let right_json = duplicate_path_json.clone();
    let (left, right) = tokio::join!(
        async move { persist_kg_import_report(&left_pool, &left_json).await },
        async move { persist_kg_import_report(&right_pool, &right_json).await },
    );

    let left_reason = assert_conflict_reason(left, &expected_reason);
    let right_reason = assert_conflict_reason(right, &expected_reason);
    assert_eq!(left_reason, right_reason);
    assert_topology_counts(&db.pool, TopologyCounts::persisted_once()).await;

    db.cleanup().await;
}

#[tokio::test]
async fn duplicate_layer_membership_conflict_is_deterministic() {
    let Some(db) = TestDb::new("duplicate_membership").await else {
        return;
    };
    let report = layered_report();
    persist_kg_import_report(&db.pool, &report.to_string())
        .await
        .expect("baseline layered KG import");

    // Membership ids are derived from (tenant, namespace, layer, node), so a
    // different id for the same pair is rejected at validation. The
    // persistence conflict is exercised by re-importing the same derived
    // membership id with conflicting row content instead.
    let mut duplicate_membership = report;
    duplicate_membership["batch_id"] = json!(h(0xd2));
    duplicate_membership["proposed_layer_memberships"][1]["local_node_rank"] = json!(1);
    let duplicate_membership_json = duplicate_membership.to_string();
    let expected_reason = format!(
        "existing dagdb_graph_layer_memberships row mismatch for {}",
        membership_id("root/knowledge-graph", 1, 0x41)
    );

    let first = persist_kg_import_report(&db.pool, &duplicate_membership_json).await;
    let second = persist_kg_import_report(&db.pool, &duplicate_membership_json).await;
    let first_reason = assert_conflict_reason(first, &expected_reason);
    let second_reason = assert_conflict_reason(second, &expected_reason);
    assert_eq!(first_reason, second_reason);
    assert_topology_counts(&db.pool, TopologyCounts::persisted_once()).await;

    db.cleanup().await;
}

#[tokio::test]
async fn rejected_layered_input_rolls_back_layer_artifacts() {
    let Some(db) = TestDb::new("rollback_rejected_layered").await else {
        return;
    };
    let mut report = layered_report();
    report["proposed_layer_memberships"][1]["layer_id"] = json!(h(0xff));

    let result = persist_kg_import_report(&db.pool, &report.to_string()).await;
    assert!(result.is_err(), "invalid layered input must be rejected");
    assert_topology_counts(&db.pool, TopologyCounts::zero()).await;

    db.cleanup().await;
}

fn assert_conflict_reason<T>(
    result: Result<T, KgImportPersistenceError>,
    expected_reason: &str,
) -> String {
    match result {
        Err(KgImportPersistenceError::Conflict { reason }) => {
            assert_eq!(reason, expected_reason);
            reason
        }
        Err(other) => panic!("expected conflict {expected_reason:?}, got {other:?}"),
        Ok(_) => panic!("expected conflict {expected_reason:?}, got Ok"),
    }
}

async fn assert_topology_counts(pool: &PgPool, expected: TopologyCounts) {
    let actual = topology_counts(pool).await;
    assert_eq!(actual, expected);
}

async fn topology_counts(pool: &PgPool) -> TopologyCounts {
    TopologyCounts {
        memory_objects: row_count(pool, "dagdb_memory_objects").await,
        catalog_entries: row_count(pool, "dagdb_catalog_entries").await,
        graph_nodes: row_count(pool, "dagdb_graph_nodes").await,
        graph_edges: row_count(pool, "dagdb_graph_edges").await,
        graph_layers: row_count(pool, "dagdb_graph_layers").await,
        layer_memberships: row_count(pool, "dagdb_graph_layer_memberships").await,
        layer_edges: row_count(pool, "dagdb_graph_layer_edges").await,
        placement_decisions: row_count(pool, "dagdb_graph_canonicalization_decisions").await,
        placement_traces: row_count(pool, "dagdb_graph_placement_traces").await,
        receipts: row_count(pool, "dagdb_receipts").await,
        idempotency_keys: row_count(pool, "dagdb_idempotency_keys").await,
    }
}

async fn row_count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .expect("count table rows")
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
            "metadata": {"source": "layered_transaction_concurrency_contract"}
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
            "metadata": {"source": "layered_transaction_concurrency_contract"}
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
