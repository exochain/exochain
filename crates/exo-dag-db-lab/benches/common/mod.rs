// Shared benchmark harness for the exo-dag-db runtime performance suite.
//
// This module is included by each criterion bench via `#[path = ...]`. It owns:
//   * live-Postgres connection URL resolution (env first, then the
//     `tools/start_dagdb_local.sh` local-dev defaults) WITHOUT ever printing
//     the URL or its embedded secret;
//   * isolated-schema setup/teardown that mirrors the contract-test harness
//     (`CREATE SCHEMA dagdb_<label>_<pid>` + apply `DAGDB_SCHEMA_SQL` /
//     `DAGDB_GRAPH_SCHEMA_SQL`) so benches never pollute the shared store;
//   * a parametric import-report generator that seeds the store to an arbitrary
//     corpus size (used for the production-scale tiers), modelled 1:1 on the
//     proven-valid contract-test fixture.
//
// Benches are dev-only; `unwrap`/`expect` are acceptable here (and are how the
// upstream exo-dag bench and the dag-db contract tests are written).
#![allow(clippy::expect_used, clippy::unwrap_used, dead_code)]

use exo_dag_db_api::{MemoryCandidateKind, MemoryCandidateUse, RiskClass};
use exo_dag_db_exchange::{
    kg_import::{KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DRY_RUN_REPORT_SCHEMA, required_trace},
    kg_writeback::{
        KgAgentWritebackHint, KgWritebackDryRunReport, KgWritebackExistingMemory,
        KgWritebackProposalRequest, build_writeback_dry_run_report,
    },
};
use exo_dag_db_postgres::postgres::{DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL};
use exo_dag_db_retrieval::kg_retrieval::{KgContextPacketPreview, KgRetrievalRequest};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

/// Env var the contract tests and the gateway both read for the live store.
pub const DATABASE_URL_ENV: &str = "EXO_DAGDB_TEST_DATABASE_URL";

const TENANT_ID: &str = "tenant-bench";
const NAMESPACE: &str = "dag-db";
const ACTOR_DID: &str = "did:exo:kg-bench";

// ---------------------------------------------------------------------------
// Named scale tiers (requirement 2). These are the real production grounding:
// `PRODUCTION_TIER` matches the ~4,326-item production corpus the audit cited;
// `BEYOND_PRODUCTION_TIER` exercises a ~10,000-item headroom case so the
// latency-vs-corpus-size curve is measured past today's synthetic ceiling.
// `SMOKE_TIER` is a small tier so the pipeline benches stay fast.
// ---------------------------------------------------------------------------

/// Small tier for the end-to-end pipeline benches (import/retrieval/writeback).
pub const SMOKE_TIER: usize = 256;
/// Production corpus size (the ~4,326-item real corpus from the audit).
pub const PRODUCTION_TIER: usize = 4_326;
/// Beyond-production headroom tier (~10,000 items).
pub const BEYOND_PRODUCTION_TIER: usize = 10_000;

/// The scale tiers measured by the latency-vs-corpus-size curve, in order.
pub const SCALE_TIERS: [usize; 2] = [PRODUCTION_TIER, BEYOND_PRODUCTION_TIER];

/// Resolve the live Postgres URL from the environment, or fall back to the
/// `tools/start_dagdb_local.sh` local-dev defaults.
///
/// Returns `None` (with a clear, secret-free skip message) when neither the env
/// var is set nor a local stack is reachable, so benches degrade exactly like
/// the contract tests instead of hanging or panicking. The resolved URL is
/// never printed.
pub fn resolve_database_url() -> Option<String> {
    if let Ok(url) = std::env::var(DATABASE_URL_ENV)
        && !url.trim().is_empty()
    {
        return Some(url);
    }
    // Mirror tools/start_dagdb_local.sh defaults (host-published dev Postgres).
    let port = std::env::var("DAGDB_POSTGRES_PORT").unwrap_or_else(|_| "5433".to_owned());
    let user = std::env::var("DAGDB_POSTGRES_USER").unwrap_or_else(|_| "exochain".to_owned());
    let password =
        std::env::var("DAGDB_POSTGRES_PASSWORD").unwrap_or_else(|_| "exochain_dev".to_owned());
    let db = std::env::var("DAGDB_POSTGRES_DB").unwrap_or_else(|_| "exochain".to_owned());
    Some(format!(
        "postgres://{user}:{password}@localhost:{port}/{db}"
    ))
}

/// Print the standard secret-free skip line and return `None`-equivalent.
pub fn skip(label: &str) {
    eprintln!(
        "skipping exo-dag-db bench {label}: no reachable Postgres \
         (set {DATABASE_URL_ENV} or start tools/start_dagdb_local.sh)"
    );
}

/// An isolated benchmark store: a dedicated schema on the shared dev database
/// with the DAG DB schema applied, plus the admin pool used to drop it.
pub struct BenchStore {
    pub pool: PgPool,
    admin_pool: PgPool,
    schema: String,
}

impl BenchStore {
    /// Provision an isolated schema and apply the DAG DB + graph schema.
    ///
    /// Returns `None` if no store is reachable; callers skip the bench. The
    /// schema name embeds the pid so concurrent bench processes never collide,
    /// mirroring the contract-test harness.
    pub async fn try_new(label: &str, max_connections: u32) -> Option<Self> {
        let database_url = resolve_database_url()?;
        let schema = format!("dagdb_bench_{label}_{}", std::process::id());
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .ok()?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#
        )))
        .execute(&admin_pool)
        .await
        .ok()?;
        sqlx::query(sqlx::AssertSqlSafe(format!(r#"CREATE SCHEMA "{schema}""#)))
            .execute(&admin_pool)
            .await
            .ok()?;

        let scoped_url = database_url_with_search_path(&database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&scoped_url)
            .await
            .ok()?;
        sqlx::raw_sql(DAGDB_SCHEMA_SQL).execute(&pool).await.ok()?;
        sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
            .execute(&pool)
            .await
            .ok()?;
        Some(Self {
            pool,
            admin_pool,
            schema,
        })
    }

    /// Close the pool and drop the isolated schema. Always call this so benches
    /// leave the shared store exactly as they found it.
    pub async fn cleanup(self) {
        self.pool.close().await;
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#,
            self.schema
        )))
        .execute(&self.admin_pool)
        .await;
        self.admin_pool.close().await;
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

// ---------------------------------------------------------------------------
// Request + writeback builders (mirror the contract-test helpers).
// ---------------------------------------------------------------------------

/// A retrieval request scoped to the bench tenant/namespace.
pub fn retrieval_request(token_budget: u32, max_memory_refs: Option<u32>) -> KgRetrievalRequest {
    KgRetrievalRequest {
        tenant_id: TENANT_ID.into(),
        namespace: NAMESPACE.into(),
        task_hash: Some(hex64(0xAA00_0000, 0)),
        task_description: None,
        token_budget,
        requested_memory_ids: Vec::new(),
        catalog_path: Some(vec!["KnowledgeGraphs".into(), "dag-db".into()]),
        max_memory_refs,
        layer_path: None,
        max_layer_depth: None,
        max_layers_selected: None,
        max_nodes_per_layer: None,
        max_layer_edges: None,
    }
}

/// Build a writeback dry-run report from a retrieved preview.
pub fn writeback_report(preview: &KgContextPacketPreview) -> KgWritebackDryRunReport {
    let citation = preview
        .citation_handles
        .first()
        .expect("bench preview has at least one citation handle")
        .clone();
    let existing_memory_id = preview
        .memory_refs
        .first()
        .expect("bench preview has at least one memory ref")
        .memory_id
        .clone();
    build_writeback_dry_run_report(KgWritebackProposalRequest {
        tenant_id: TENANT_ID.into(),
        namespace: NAMESPACE.into(),
        requesting_agent_did: "did:exo:kg-bench-agent".into(),
        context_packet: preview.clone(),
        hint: KgAgentWritebackHint {
            source_request_id: "bench-source-request".into(),
            parent_context_packet_id: preview.context_packet_id.clone(),
            route_hint_id: preview.route_hint_id.clone(),
            task_hash: hex64(0xAA00_0000, 0),
            answer_hash: Some(hex64(0x3000_0000, 0)),
            output_hash: None,
            candidate_kind: MemoryCandidateKind::Summary,
            summary: "bench writeback summary".into(),
            citation_handles: vec![citation.handle.clone()],
            evidence_receipts: vec![citation.latest_receipt_hash.clone()],
            risk_hint: RiskClass::R1,
            allowed_future_uses: vec![MemoryCandidateUse::Routing, MemoryCandidateUse::Audit],
            reason_to_remember: "bench writeback fixture".into(),
            keyword_texts: Vec::new(),
            contradiction_refs: Vec::new(),
            supersession_refs: Vec::new(),
        },
        existing_memory: vec![KgWritebackExistingMemory {
            memory_id: existing_memory_id,
            payload_hash: hex64(0x3000_0000, 0),
            summary: "bench writeback summary".into(),
        }],
    })
    .expect("build bench writeback dry-run report")
}

// ---------------------------------------------------------------------------
// Parametric import-report generator (requirement 2: real scale seeding).
//
// Produces a valid dry-run import report with `count` memories, each carrying
// its own catalog entry, graph node, validation report, placement decision, and
// the receipt intents those rows require — a 1:1 expansion of the contract-test
// fixture. Consecutive memories are linked by one graph edge so retrieval has
// real graph structure to walk.
// ---------------------------------------------------------------------------

/// Build a scale import report JSON seeding `count` memory rows.
#[must_use]
pub fn scale_import_report_json(count: usize) -> String {
    assert!(count >= 1, "scale tier must seed at least one memory");
    let mut memories = Vec::with_capacity(count);
    let mut catalogs = Vec::with_capacity(count);
    let mut graph_nodes = Vec::with_capacity(count);
    let mut validation_reports = Vec::with_capacity(count);
    let mut placements = Vec::with_capacity(count);
    let mut receipts = Vec::with_capacity(count * 4);
    let mut graph_edges = Vec::with_capacity(count.saturating_sub(1));
    let mut required_edges = Vec::with_capacity(count.saturating_sub(1));

    for index in 0..count {
        let idx = u32::try_from(index).expect("scale tier index fits u32");
        let memory_id = hex64(0x1000_0000, idx);
        let source_hash = hex64(0x2000_0000, idx);
        let payload_hash = hex64(0x2100_0000, idx);
        let catalog_id = hex64(0x3000_0000, idx);
        let graph_node_id = hex64(0x4000_0000, idx);
        let validation_report_id = hex64(0x7000_0000, idx);
        let placement_id = hex64(0x6000_0000, idx);
        let validator_report = hex64(0x6600_0000, idx);
        let memory_receipt = hex64(0x8000_0000, idx);
        let catalog_receipt = hex64(0x8200_0000, idx);
        let validation_receipt = hex64(0x8400_0000, idx);

        memories.push(memory_record(
            &memory_id,
            &source_hash,
            &payload_hash,
            idx,
            &memory_receipt,
        ));
        catalogs.push(catalog_entry(
            &catalog_id,
            &memory_id,
            &source_hash,
            &payload_hash,
            idx,
            &catalog_receipt,
        ));
        graph_nodes.push(graph_node(&graph_node_id, &memory_id));
        validation_reports.push(validation_report(&validation_report_id, &memory_id));
        placements.push(placement(
            &placement_id,
            &memory_id,
            &validator_report,
            &memory_receipt,
        ));
        receipts.push(receipt(
            &memory_receipt,
            "memory",
            &memory_id,
            "intake_created",
        ));
        receipts.push(receipt(
            &catalog_receipt,
            "catalog",
            &catalog_id,
            "memory_approved",
        ));
        receipts.push(receipt(
            &validation_receipt,
            "validation_report",
            &validation_report_id,
            "validation_created",
        ));
    }

    // Link consecutive memories with one active graph edge each.
    for index in 1..count {
        let idx = u32::try_from(index).expect("scale edge index fits u32");
        let from = hex64(0x1000_0000, idx - 1);
        let to = hex64(0x1000_0000, idx);
        let edge_id = hex64(0x5000_0000, idx);
        let edge_receipt = hex64(0x9100_0000, idx);
        graph_edges.push(json!({
            "graph_edge_id": edge_id,
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "graph_style": "semantic_catalog_graph",
            "from_memory_id": from,
            "to_memory_id": to,
            "edge_kind": "related_to",
            "source_edge_kind": "wikilink",
            "receipt_intent_id": edge_receipt
        }));
        required_edges.push(json!({
            "required_edge_id": edge_id,
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "graph_style": "semantic_catalog_graph",
            "from_memory_id": from,
            "to_memory_id": to,
            "edge_kind": "related_to",
            "status": "proposed"
        }));
        receipts.push(receipt(
            &edge_receipt,
            "memory",
            &edge_id,
            "validation_created",
        ));
    }

    json!({
        "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
        "graph_root": "KnowledgeGraphs/dag-db",
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "actor_did": ACTOR_DID,
        "batch_id": hex64(0x0100_0000, 0),
        "dry_run_only": true,
        "postgres_writes": false,
        "raw_markdown_included": false,
        "proposed_memory_records": memories,
        "proposed_catalog_entries": catalogs,
        "proposed_graph_nodes": graph_nodes,
        "proposed_graph_edges": graph_edges,
        "proposed_required_edges": required_edges,
        "proposed_placement_decisions": placements,
        "proposed_receipt_intents": receipts,
        "proposed_validation_reports": validation_reports,
        "proposed_governance_reviews": [],
        "proposed_graph_view_refreshes": [],
        "proposed_route_invalidations": [],
        "proposed_subdag_boundaries": [],
        "rollback_plan": {},
        "placement_governance_summary": {},
        "review_items": [],
        "warnings": []
    })
    .to_string()
}

fn memory_record(
    memory_id: &str,
    source_hash: &str,
    payload_hash: &str,
    index: u32,
    receipt_intent_id: &str,
) -> JsonValue {
    json!({
        "memory_id": memory_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "source_path": format!("KnowledgeGraphs/dag-db/bench_{index:06}.md"),
        "candidate_id": format!("bench_{index:06}"),
        "node_type": "source",
        "source_type": "generated",
        "source_hash": source_hash,
        "payload_hash": payload_hash,
        "owner_did": ACTOR_DID,
        "controller_did": ACTOR_DID,
        "submitted_by_did": ACTOR_DID,
        "consent_purpose": "retrieval",
        "title": safe(&format!("bench title {index:06}")),
        "summary": safe(&format!("bench summary {index:06}")),
        "keywords": [],
        "catalog_path": ["KnowledgeGraphs", "dag-db"],
        "risk_class": "R1",
        "risk_bp": 100,
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "status": "pending",
        "receipt_intent_id": receipt_intent_id
    })
}

fn catalog_entry(
    catalog_id: &str,
    memory_id: &str,
    source_hash: &str,
    payload_hash: &str,
    index: u32,
    receipt_intent_id: &str,
) -> JsonValue {
    json!({
        "catalog_id": catalog_id,
        "memory_id": memory_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "catalog_path": ["KnowledgeGraphs", "dag-db"],
        "catalog_level": 2,
        "title": safe(&format!("bench catalog {index:06}")),
        "summary": safe(&format!("bench catalog summary {index:06}")),
        "payload_hash": payload_hash,
        "source_hash": source_hash,
        "status": "pending",
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "receipt_intent_id": receipt_intent_id
    })
}

fn graph_node(graph_node_id: &str, memory_id: &str) -> JsonValue {
    json!({
        "graph_node_id": graph_node_id,
        "memory_id": memory_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "graph_style": "semantic_catalog_graph",
        "node_kind": "canonical",
        "catalog_path": ["KnowledgeGraphs", "dag-db"]
    })
}

fn placement(
    placement_id: &str,
    memory_id: &str,
    validator_report: &str,
    receipt_intent_id: &str,
) -> JsonValue {
    json!({
        "placement_decision_id": placement_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "input_memory_id": memory_id,
        "placement_trace": required_trace(),
        "canonicalization_decision": {
            "decision_kind": "new_canonical",
            "decision_reason": "bench fixture",
            "confidence_bp": 0,
            "risk_class": "R1",
            "validator_status": "pending",
            "matched_memory_ids": [],
            "canonical_memory_id": null,
            "required_edges_to_create": []
        },
        "similarity_results": [],
        "validator_report": validator_report,
        "receipt_intent_id": receipt_intent_id
    })
}

fn receipt(
    receipt_intent_id: &str,
    subject_kind: &str,
    subject_id: &str,
    event_type: &str,
) -> JsonValue {
    json!({
        "receipt_intent_id": receipt_intent_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "event_type": event_type,
        "actor_did": ACTOR_DID,
        "reason": "bench fixture"
    })
}

fn validation_report(validation_report_id: &str, subject_id: &str) -> JsonValue {
    json!({
        "validation_report_id": validation_report_id,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "subject_kind": "memory",
        "subject_id": subject_id,
        "validator_did": ACTOR_DID,
        "input_hash": hex64(0x7100_0000, 0),
        "policy_hash": hex64(0x7200_0000, 0),
        "validation_status": "pending",
        "risk_class": "R1",
        "risk_bp": 100,
        "decision": "allow",
        "notes": safe("bench validation")
    })
}

fn safe(text: &str) -> JsonValue {
    json!({
        "decision": "allow",
        "text": text,
        "redaction_codes": [],
        "original_hash": hex64(0xEF00_0000, 0),
        "truncated": false,
        "byte_len": text.len()
    })
}

/// Deterministic, unique 64-hex-character id derived from a domain tag and an
/// index. `domain` separates id spaces (memory/catalog/graph/...); `index`
/// makes each row unique. Distinct (domain, index) pairs never collide because
/// the 64-bit value `domain << 32 | index` is unique and is rendered in the low
/// 16 hex digits.
#[must_use]
pub fn hex64(domain: u32, index: u32) -> String {
    let value = (u64::from(domain) << 32) | u64::from(index);
    format!("{value:064x}")
}
