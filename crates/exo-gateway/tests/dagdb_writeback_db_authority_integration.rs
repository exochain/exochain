// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! ULTRAPLAN GAP-012 / T2: the DAG DB write gate authorizes against REAL
//! ExoChain consent/identity database state via the request-time resolver
//! (`resolve_gatekeeper_service_from_db`), not an in-memory dev profile.
//!
//! Unlike `dagdb_route_integration_contract.rs` — which installs an in-memory
//! gatekeeper profile and never seeds the adjudication tables — these tests
//! install NO profile, so the production DB resolver path is exercised:
//!   * a registered agent (active `consent_records` row scoped to the
//!     tenant-qualified writeback scope + a `did_documents` row carrying the
//!     agent's Ed25519 key) authorizes a writeback and persists a receipt;
//!   * an unregistered agent (no rows) fails closed with no DB write;
//!   * a forged signature fails closed with no DB write.
//!
//! These tests connect to a live Postgres via `EXO_DAGDB_TEST_DATABASE_URL`
//! (same env the route contract test uses) and run in an isolated schema. They
//! are skipped when the env var is unset.
//!
//! ## Served level: gateway DB authority (T6 / GAP-012)
//!
//! This drives the REAL served path — `exo_gateway::server::build_router` (a
//! real axum router) + a real `PgPool` + the real `DagDbGatekeeperService`, with
//! NO injected in-memory gatekeeper profile — into Postgres. It is **gateway-
//! served**, by design: this file proves the production `exo-gateway`
//! persistence and authority route against live Postgres. `exo-node` now
//! compiles the production gateway default and serves DAG DB through the live
//! MCP gateway proxy when `EXO_DAGDB_GATEWAY_URL`, `EXO_DAGDB_GATEWAY_BEARER_TOKEN`,
//! `EXO_DAGDB_TENANT_ID`, and `EXO_DAGDB_NAMESPACE` are configured; node proxy
//! behavior is covered by the MCP DAG DB tool tests rather than this gateway DB
//! authority integration.
//!
//! As of T6 this path also exercises the constitutional invariant subset
//! (`dagdb_invariant_set`): the gateway now threads a real `InvariantContext`
//! built from the resolved consent/identity state into the gated persist call,
//! so a successful registered writeback below is evidence the invariant subset
//! passes for a legitimately-authorized agent (it does not deadlock the write),
//! while the unregistered/forged cases still fail closed.

#![cfg(feature = "production-db")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, RwLock};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use exo_api::dagdb::{DagDbImportRequest, DagDbWritebackRequest};
use exo_core::{PublicKey, Timestamp, crypto::KeyPair};
use exo_dag_db_exchange::kg_import::{
    KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
    required_trace,
};
use exo_dag_db_postgres::{
    persistent_context::build_persistent_graph_context_selection,
    postgres::{
        DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL,
    },
};
use exo_gatekeeper::{sign_write_payload, usage_event_payload_hash};
use exo_gateway::{
    dagdb::{
        DagDbRouteContext, selection_request_from_writeback,
        set_route_context_for_integration_tests,
    },
    db,
    server::{AppState, build_router},
};
use exo_identity::{
    did::{DidDocument, VerificationMethod},
    registry::LocalDidRegistry,
};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

const TENANT_ID: &str = "tenant-db-authority";
const NAMESPACE: &str = "primary";
const REGISTERED_AGENT_DID: &str = "did:exo:db-authority-agent";
const UNREGISTERED_AGENT_DID: &str = "did:exo:db-authority-stranger";
const BAILOR_DID: &str = "did:exo:db-authority-bailor";
const REGISTERED_BEARER: &str = "db-authority-token";
const UNREGISTERED_BEARER: &str = "db-authority-stranger-token";

// Mirror of `dagdb::tenant_writeback_scope`: tenant-qualified writeback scope
// encoded into the `consent_records.scope` column (no tenant column exists).
fn tenant_writeback_scope(tenant_id: &str) -> String {
    format!("dag-db:writeback:{tenant_id}")
}

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let database_url = std::env::var(KG_IMPORT_DATABASE_URL_ENV).ok()?;
        let schema = format!("dagdb_db_authority_{label}_{}", std::process::id());
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
        sqlx::raw_sql(DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB telemetry-facet node_type schema");
        // Auth + adjudication tables the production resolver and session
        // binding query. The route contract test creates only users/sessions;
        // here we additionally create the consent_records and did_documents
        // tables the DB resolver reads.
        sqlx::raw_sql(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                did TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                roles JSONB NOT NULL DEFAULT '[]',
                tenant_id TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                pace_status TEXT NOT NULL DEFAULT 'Unenrolled',
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                actor_did TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE
            );
            CREATE TABLE IF NOT EXISTS consent_records (
                subject_did   TEXT    NOT NULL,
                actor_did     TEXT    NOT NULL,
                scope         TEXT    NOT NULL,
                bailment_type TEXT    NOT NULL DEFAULT 'standard',
                status        TEXT    NOT NULL DEFAULT 'active',
                created_at    BIGINT  NOT NULL,
                expires_at    BIGINT,
                PRIMARY KEY (subject_did, actor_did, scope)
            );
            CREATE TABLE IF NOT EXISTS did_documents (
                did TEXT PRIMARY KEY,
                document JSONB NOT NULL,
                created_at_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("apply auth + adjudication tables");
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

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

async fn insert_session_user(pool: &PgPool, token: &str, did: &str, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO users \
         (did, display_name, email, roles, tenant_id, created_at, status, pace_status, \
          password_hash, salt, mfa_enabled) \
         VALUES ($1, $2, $3, '[]'::jsonb, $4, $5, 'Active', 'Unenrolled', 'hash', 'salt', false)",
    )
    .bind(did)
    .bind("DAG DB Agent")
    .bind(format!("{did}@example.invalid"))
    .bind(tenant_id)
    .bind(10_000_i64)
    .execute(pool)
    .await
    .expect("insert test user");
    sqlx::query(
        "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
         VALUES ($1, $2, $3, $4, false)",
    )
    .bind(token)
    .bind(did)
    .bind(10_000_i64)
    .bind(4_102_444_800_000_i64)
    .execute(pool)
    .await
    .expect("insert test session");
}

/// Seed an active consent record granting `agent_did` the tenant-qualified
/// writeback scope, with `bailor_did` as the entrusting subject.
async fn insert_active_consent(pool: &PgPool, bailor_did: &str, agent_did: &str, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO consent_records \
         (subject_did, actor_did, scope, bailment_type, status, created_at) \
         VALUES ($1, $2, $3, 'standard', 'active', 0)",
    )
    .bind(bailor_did)
    .bind(agent_did)
    .bind(tenant_writeback_scope(tenant_id))
    .execute(pool)
    .await
    .expect("insert active consent record");
}

/// A DID document whose single active verification method carries `public_key`.
fn did_document_with_ed25519_key(did_str: &str, public_key: &PublicKey) -> DidDocument {
    let did = exo_core::Did::new(did_str).expect("valid DID");
    let multibase = format!("z{}", bs58::encode(public_key.as_bytes()).into_string());
    DidDocument {
        id: did.clone(),
        public_keys: vec![*public_key],
        authentication: vec![],
        verification_methods: vec![VerificationMethod {
            id: format!("{did_str}#key-1"),
            key_type: "Ed25519VerificationKey2020".into(),
            controller: did.clone(),
            public_key_multibase: multibase,
            version: 1,
            active: true,
            valid_from: 0,
            revoked_at: None,
        }],
        hybrid_verification_methods: vec![],
        service_endpoints: vec![],
        created: Timestamp::ZERO,
        updated: Timestamp::ZERO,
        revoked: false,
    }
}

fn writeback_request(
    agent_did: &str,
    idempotency_key: &str,
    answer_hash: &str,
) -> DagDbWritebackRequest {
    DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        requesting_agent_did: agent_did.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: answer_hash.to_owned(),
        route_id: h(0x90),
        context_packet_id: h(0xa0),
        validation_report_id: h(0xb0),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: Some(vec![h(0xc0)]),
        safety_score_id: None,
        keyword_texts: Some(vec!["answer".to_owned()]),
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    }
}

async fn writeback_signature(
    pool: &PgPool,
    keypair: &KeyPair,
    request: &DagDbWritebackRequest,
) -> String {
    let selection = build_persistent_graph_context_selection(
        pool,
        &selection_request_from_writeback(request).expect("selection request for writeback"),
    )
    .await
    .expect("selection for signature");
    let payload_hash = usage_event_payload_hash(&selection.selection).expect("payload hash");
    sign_write_payload(keypair, &payload_hash).expect("writeback signature")
}

fn import_request() -> DagDbImportRequest {
    DagDbImportRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-db-import-seed".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        source_hash: h(0x01),
        requester_did: REGISTERED_AGENT_DID.to_owned(),
        import_report: base_report(),
    }
}

fn selection_request_for_import(
    request: &DagDbImportRequest,
) -> exo_api::dagdb::DagDbGraphContextSelectionRequest {
    exo_api::dagdb::DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.idempotency_key.clone(),
        task: format!("import:{}", request.source_hash),
        task_hash: request.source_hash.clone(),
        token_budget: 2_048,
        max_memory_refs: 1,
        catalog_hints: Vec::new(),
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

async fn import_signature(
    pool: &PgPool,
    keypair: &KeyPair,
    request: &DagDbImportRequest,
) -> String {
    let selection =
        build_persistent_graph_context_selection(pool, &selection_request_for_import(request))
            .await
            .expect("selection for import signature");
    sign_write_payload(
        keypair,
        &usage_event_payload_hash(&selection.selection).expect("import payload hash"),
    )
    .expect("import signature")
}

fn scoped_import_post(
    bearer: &str,
    body: &DagDbImportRequest,
    signature: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/dag-db/import")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header("x-exo-tenant-id", TENANT_ID)
        .header("x-exo-namespace", NAMESPACE)
        .header(
            "x-exo-authority-scope",
            format!("dagdb:import:{TENANT_ID}:{NAMESPACE}"),
        )
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(signature) = signature {
        builder = builder.header("x-exo-write-signature", signature);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("request")
}

fn scoped_writeback_post(
    bearer: &str,
    body: &DagDbWritebackRequest,
    signature: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/dag-db/writeback")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header("x-exo-tenant-id", TENANT_ID)
        .header("x-exo-namespace", NAMESPACE)
        .header(
            "x-exo-authority-scope",
            format!("dagdb:writeback:{TENANT_ID}:{NAMESPACE}"),
        )
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(signature) = signature {
        builder = builder.header("x-exo-write-signature", signature);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("request")
}

async fn receipt_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_receipts WHERE tenant_id = $1 AND namespace = $2",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_one(pool)
    .await
    .expect("count receipts")
}

async fn response_json(response: axum::response::Response) -> JsonValue {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

// ---------------------------------------------------------------------------
// KG import report fixture (copied from dagdb_route_integration_contract.rs) —
// used to seed routable graph memories so the writeback selection succeeds.
// ---------------------------------------------------------------------------

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

fn memory(id: u8, source: u8, path: &str, title: &str) -> JsonValue {
    json!({
        "memory_id": h(id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "source_path": path,
        "candidate_id": title,
        "node_type": "source",
        "source_type": "generated",
        "source_hash": h(source),
        "payload_hash": h(id.wrapping_add(0x20)),
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
        "receipt_intent_id": h(id.wrapping_add(0x70))
    })
}

fn catalog(id: u8, memory_id: u8, source: u8, title: &str) -> JsonValue {
    json!({
        "catalog_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "catalog_path": ["KnowledgeGraphs", "dag-db"],
        "catalog_level": 2,
        "title": safe(title),
        "summary": safe("catalog summary"),
        "payload_hash": h(id.wrapping_add(0x20)),
        "source_hash": h(source),
        "status": "pending",
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "receipt_intent_id": h(id.wrapping_add(0x52))
    })
}

fn graph_node(id: u8, memory_id: u8) -> JsonValue {
    json!({
        "graph_node_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "graph_style": "semantic_catalog_graph",
        "node_kind": "canonical",
        "catalog_path": ["KnowledgeGraphs", "dag-db"]
    })
}

fn placement(id: u8, memory_id: u8, receipt_id: u8) -> JsonValue {
    json!({
        "placement_decision_id": h(id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
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
        "validator_report": h(memory_id.wrapping_add(0x60)),
        "receipt_intent_id": h(receipt_id)
    })
}

fn receipt(id: u8, subject_kind: &str, subject_id: u8, event_type: &str) -> JsonValue {
    json!({
        "receipt_intent_id": h(id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "subject_kind": subject_kind,
        "subject_id": h(subject_id),
        "event_type": event_type,
        "actor_did": REGISTERED_AGENT_DID,
        "reason": "synthetic fixture"
    })
}

fn validation_report(id: u8, subject_id: u8) -> JsonValue {
    json!({
        "validation_report_id": h(id),
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "subject_kind": "memory",
        "subject_id": h(subject_id),
        "validator_did": "did:exo:kg-importer",
        "input_hash": h(id.wrapping_add(0x10)),
        "policy_hash": h(id.wrapping_add(0x20)),
        "validation_status": "pending",
        "risk_class": "R1",
        "risk_bp": 100,
        "decision": "allow",
        "notes": safe("synthetic validation")
    })
}

fn base_report() -> JsonValue {
    json!({
        "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
        "graph_root": "KnowledgeGraphs/dag-db",
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "actor_did": REGISTERED_AGENT_DID,
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
                "tenant_id": TENANT_ID,
                "namespace": NAMESPACE,
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
                "tenant_id": TENANT_ID,
                "namespace": NAMESPACE,
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
        "warnings": [],
        "errors": []
    })
}

/// All three DB-authority scenarios run inside ONE test: the route-context
/// override is a process-wide `OnceLock`, so a single context/schema/router is
/// shared across the registered, unregistered, and forged cases (mirrors the
/// single-function shape of `dagdb_route_integration_contract.rs`).
#[tokio::test]
async fn writeback_authorizes_against_real_db_consent_and_identity_state() {
    let Some(db) = TestDb::new("writeback").await else {
        return; // EXO_DAGDB_TEST_DATABASE_URL unset — skip
    };

    let keypair = KeyPair::generate();
    let forger = KeyPair::generate();
    // No in-memory profile is installed: the production DB resolver path runs.
    let ctx = Arc::new(DagDbRouteContext::from_pool(Some(db.pool.clone())));
    set_route_context_for_integration_tests(ctx.clone());

    // Registered agent: valid session + active tenant-scoped consent + DID doc
    // carrying the agent's real Ed25519 key.
    insert_session_user(&db.pool, REGISTERED_BEARER, REGISTERED_AGENT_DID, TENANT_ID).await;
    insert_active_consent(&db.pool, BAILOR_DID, REGISTERED_AGENT_DID, TENANT_ID).await;
    let agent_doc = did_document_with_ed25519_key(REGISTERED_AGENT_DID, keypair.public_key());
    assert!(
        db::insert_did_document(&db.pool, &agent_doc).await.unwrap(),
        "registered agent DID document must be seeded"
    );
    // Unregistered agent: valid session (so session binding passes) but NO
    // consent_records row and NO did_documents row.
    insert_session_user(
        &db.pool,
        UNREGISTERED_BEARER,
        UNREGISTERED_AGENT_DID,
        TENANT_ID,
    )
    .await;

    let app = build_router(AppState::new(
        Some(db.pool.clone()),
        Arc::new(RwLock::new(LocalDidRegistry::new())),
    ));

    // --- Seed: import routes now fail closed until distinct import consent
    // exists. Prove writeback consent is insufficient, then seed graph memories
    // directly so the writeback resolver cases below still exercise real DB
    // authority.
    let import = import_request();
    let import_sig = import_signature(&db.pool, &keypair, &import).await;
    let import_response = app
        .clone()
        .oneshot(scoped_import_post(
            REGISTERED_BEARER,
            &import,
            Some(import_sig),
        ))
        .await
        .expect("import response");
    let import_status = import_response.status();
    let import_body = response_json(import_response).await;
    assert_eq!(
        import_status,
        StatusCode::FORBIDDEN,
        "writeback consent must not authorize import"
    );
    assert_eq!(import_body["error_code"], "consent_denied");
    assert!(
        import_body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("distinct import/export consent"),
        "import denial must identify the missing distinct consent"
    );
    let import_seed_json =
        serde_json::to_string(&import.import_report).expect("seed import report json");
    exo_dag_db_postgres::postgres::kg_import::persist_kg_import_report(&db.pool, &import_seed_json)
        .await
        .expect("seed DAG DB graph rows for writeback authority contract");

    // --- Case 1: registered agent authorizes a writeback and persists. -------
    let registered_request =
        writeback_request(REGISTERED_AGENT_DID, "idem-db-registered", &h(0x80));
    let registered_signature = writeback_signature(&db.pool, &keypair, &registered_request).await;
    let receipts_before = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let registered_response = app
        .clone()
        .oneshot(scoped_writeback_post(
            REGISTERED_BEARER,
            &registered_request,
            Some(registered_signature),
        ))
        .await
        .expect("registered writeback response");
    assert_eq!(
        registered_response.status(),
        StatusCode::OK,
        "registered + consented + signed writeback must authorize against DB state"
    );
    let registered_body = response_json(registered_response).await;
    assert!(!registered_body["receipt_hash"].as_str().unwrap().is_empty());
    let receipts_after_registered = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    assert!(
        receipts_after_registered > receipts_before,
        "authorized writeback must append a receipt"
    );

    // --- Case 2: unregistered agent fails closed with no write. --------------
    let unregistered_request =
        writeback_request(UNREGISTERED_AGENT_DID, "idem-db-unregistered", &h(0x81));
    let unregistered_signature =
        writeback_signature(&db.pool, &keypair, &unregistered_request).await;
    let unregistered_response = app
        .clone()
        .oneshot(scoped_writeback_post(
            UNREGISTERED_BEARER,
            &unregistered_request,
            Some(unregistered_signature),
        ))
        .await
        .expect("unregistered writeback response");
    assert!(
        unregistered_response.status().is_client_error()
            || unregistered_response.status().is_server_error(),
        "unregistered agent must fail closed, got {}",
        unregistered_response.status()
    );
    let receipts_after_unregistered = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    assert_eq!(
        receipts_after_unregistered, receipts_after_registered,
        "unregistered agent must not persist any receipt"
    );

    // --- Case 3: forged signature fails closed with no write. ----------------
    let forged_request = writeback_request(REGISTERED_AGENT_DID, "idem-db-forged", &h(0x82));
    let forged_signature = writeback_signature(&db.pool, &forger, &forged_request).await;
    let forged_response = app
        .clone()
        .oneshot(scoped_writeback_post(
            REGISTERED_BEARER,
            &forged_request,
            Some(forged_signature),
        ))
        .await
        .expect("forged writeback response");
    assert_eq!(
        forged_response.status(),
        StatusCode::FORBIDDEN,
        "forged signature must fail closed with provenance denial"
    );
    let forged_body = response_json(forged_response).await;
    assert_eq!(forged_body["error_code"], "provenance_denied");
    let receipts_after_forged = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    assert_eq!(
        receipts_after_forged, receipts_after_registered,
        "forged signature must not persist any receipt"
    );

    db.cleanup().await;
}
