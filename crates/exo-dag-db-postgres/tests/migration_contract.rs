#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{fs, path::PathBuf, process};

use exo_dag_db_postgres::postgres::{
    CATALOG_ROOT_HASH_SEMANTICS, DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
    DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL,
    DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL, DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL,
    DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL, DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
    DAGDB_TENANT_RLS_SCHEMA_SQL, bind_tenant_context, init_pool, run_migrations_in_schema,
};
use sqlx::{Connection, PgConnection, Pool, Postgres, Row, Transaction, migrate::Migrator};

const EXPECTED_TABLES: &[&str] = &[
    "dagdb_agent_safety_scores",
    "dagdb_benchmark_runs",
    "dagdb_catalog_entries",
    "dagdb_context_packet_records",
    "dagdb_context_packets",
    "dagdb_continuation_records",
    "dagdb_council_decisions",
    "dagdb_dag_outbox",
    "dagdb_default_routes",
    "dagdb_export_challenges",
    "dagdb_exports",
    "dagdb_gateway_state_records",
    "dagdb_graph_canonicalization_decisions",
    "dagdb_graph_edge_tombstones",
    "dagdb_graph_edges",
    "dagdb_graph_layer_edges",
    "dagdb_graph_layer_memberships",
    "dagdb_graph_layers",
    "dagdb_graph_nodes",
    "dagdb_graph_placement_traces",
    "dagdb_graph_route_invalidations",
    "dagdb_graph_similarity_results",
    "dagdb_graph_views",
    "dagdb_idempotency_keys",
    "dagdb_inbound_agent_credentials",
    "dagdb_lifecycle_actions",
    "dagdb_lifecycle_rollbacks",
    "dagdb_memory_edges",
    "dagdb_memory_objects",
    "dagdb_node_commit_certificates",
    "dagdb_node_committed",
    "dagdb_node_consensus_meta",
    "dagdb_node_consensus_votes",
    "dagdb_node_dag_nodes",
    "dagdb_node_dag_parents",
    "dagdb_node_economy_anchors",
    "dagdb_node_economy_meta",
    "dagdb_node_economy_objects",
    "dagdb_node_trust_receipts",
    "dagdb_node_validators",
    "dagdb_receipts",
    "dagdb_root_bundle_receipts",
    "dagdb_route_invalidation_events",
    "dagdb_route_receipts",
    "dagdb_subject_receipt_heads",
    "dagdb_validation_reports",
    "dagdb_zerodentity_records",
];

const EXPECTED_TENANT_RLS_TABLES: &[&str] = &[
    "dagdb_agent_safety_scores",
    "dagdb_catalog_entries",
    "dagdb_context_packet_records",
    "dagdb_context_packets",
    "dagdb_continuation_records",
    "dagdb_council_decisions",
    "dagdb_dag_outbox",
    "dagdb_default_routes",
    "dagdb_export_challenges",
    "dagdb_exports",
    "dagdb_gateway_state_records",
    "dagdb_graph_canonicalization_decisions",
    "dagdb_graph_edge_tombstones",
    "dagdb_graph_edges",
    "dagdb_graph_layer_edges",
    "dagdb_graph_layer_memberships",
    "dagdb_graph_layers",
    "dagdb_graph_nodes",
    "dagdb_graph_placement_traces",
    "dagdb_graph_route_invalidations",
    "dagdb_graph_similarity_results",
    "dagdb_graph_views",
    "dagdb_idempotency_keys",
    "dagdb_inbound_agent_credentials",
    "dagdb_lifecycle_actions",
    "dagdb_memory_edges",
    "dagdb_memory_objects",
    "dagdb_node_commit_certificates",
    "dagdb_node_committed",
    "dagdb_node_consensus_meta",
    "dagdb_node_consensus_votes",
    "dagdb_node_dag_nodes",
    "dagdb_node_dag_parents",
    "dagdb_node_economy_anchors",
    "dagdb_node_economy_meta",
    "dagdb_node_economy_objects",
    "dagdb_node_trust_receipts",
    "dagdb_node_validators",
    "dagdb_receipts",
    "dagdb_route_invalidation_events",
    "dagdb_route_receipts",
    "dagdb_subject_receipt_heads",
    "dagdb_validation_reports",
    "dagdb_zerodentity_records",
];

const PR708_NEW_TENANT_RLS_TABLES: &[&str] = &[
    "dagdb_node_dag_nodes",
    "dagdb_node_dag_parents",
    "dagdb_node_committed",
    "dagdb_node_consensus_meta",
    "dagdb_node_consensus_votes",
    "dagdb_node_commit_certificates",
    "dagdb_node_validators",
    "dagdb_node_trust_receipts",
    "dagdb_node_economy_objects",
    "dagdb_node_economy_anchors",
    "dagdb_node_economy_meta",
    "dagdb_zerodentity_records",
    "dagdb_gateway_state_records",
];

const PR708_NEW_MIGRATION_VERSIONS: &[i64] = &[
    20260623000001,
    20260623000002,
    20260623000003,
    20260623000004,
    20260623000005,
    20260623000006,
];

const LAST_SUCCESSFUL_DEPLOYED_MIGRATION_FILES: &[&str] = &[
    "20260505000001_create_dagdb_schema.sql",
    "20260505000002_create_dagdb_graph_schema.sql",
    "20260511000001_create_dagdb_export_persistence_schema.sql",
    "20260511000002_create_dagdb_export_finality_outbox_schema.sql",
    "20260602000001_create_dagdb_graph_edge_tombstones.sql",
    "20260602000002_create_dagdb_layered_graph_schema.sql",
    "20260607000001_create_prd17_default_route_schema.sql",
    "20260607000002_create_prd17_context_packet_schema.sql",
    "20260607000003_create_prd17_lifecycle_schema.sql",
    "20260612000001_create_dagdb_telemetry_facet_node_type.sql",
    "20260612000002_add_dagdb_graph_layers_aggregate_summary.sql",
    "20260612000003_add_dagdb_memory_deep_detail_summary.sql",
    "20260619000001_enable_dagdb_tenant_rls.sql",
    "20260620000001_add_dagdb_operational_receipt_event_types.sql",
];

const OPERATIONAL_RECEIPT_EVENT_TYPES: &[&str] = &[
    "dagdb_approval_request_submitted",
    "dagdb_approval_granted",
    "dagdb_approval_denied",
    "dagdb_record_accepted",
    "dagdb_import_completed",
    "dagdb_export_completed",
    "dagdb_replay_detected",
    "dagdb_idempotency_conflict",
    "dagdb_rls_tenant_violation",
    "dagdb_signature_failure",
    "dagdb_council_operator_decision",
];

const EXPECTED_INDEXES: &[(&str, &str)] = &[
    (
        "idx_dagdb_receipts_subject",
        "dagdb_receipts USING btree (tenant_id, namespace, subject_kind, subject_id, seq DESC)",
    ),
    (
        "idx_dagdb_receipts_event_type",
        "dagdb_receipts USING btree (tenant_id, namespace, event_type, event_hlc_physical_ms DESC, event_hlc_logical DESC)",
    ),
    (
        "idx_dagdb_root_bundle_receipts_ceremony",
        "dagdb_root_bundle_receipts USING btree (ceremony_id, verified_at_physical_ms DESC, verified_at_logical DESC)",
    ),
    (
        "uq_dagdb_memory_active_duplicate",
        "UNIQUE INDEX uq_dagdb_memory_active_duplicate ON",
    ),
    (
        "idx_dagdb_memory_status",
        "dagdb_memory_objects USING btree (tenant_id, namespace, status, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_memory_risk",
        "dagdb_memory_objects USING btree (tenant_id, namespace, risk_class, risk_bp DESC)",
    ),
    (
        "idx_dagdb_memory_receipt",
        "dagdb_memory_objects USING btree (latest_receipt_hash)",
    ),
    (
        "idx_dagdb_memory_dag_finality",
        "dagdb_memory_objects USING btree (tenant_id, namespace, dag_finality_status, status)",
    ),
    (
        "idx_dagdb_edges_to_type",
        "dagdb_memory_edges USING btree (tenant_id, namespace, to_memory_id, edge_type)",
    ),
    (
        "idx_dagdb_catalog_level",
        "dagdb_catalog_entries USING btree (tenant_id, namespace, catalog_level, catalog_id)",
    ),
    (
        "idx_dagdb_catalog_status",
        "dagdb_catalog_entries USING btree (tenant_id, namespace, status, validation_status, council_status)",
    ),
    (
        "idx_dagdb_routes_status",
        "dagdb_route_receipts USING btree (tenant_id, namespace, status, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_routes_task",
        "dagdb_route_receipts USING btree (tenant_id, namespace, task_signature_hash, route_score_bp DESC, route_id)",
    ),
    ("idx_dagdb_routes_stale", "WHERE (status = 'active'::text)"),
    (
        "idx_dagdb_routes_finality",
        "dagdb_route_receipts USING btree (tenant_id, namespace, dag_finality_status, status)",
    ),
    (
        "idx_dagdb_packets_validation",
        "dagdb_context_packets USING btree (tenant_id, namespace, validation_status, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_packets_request",
        "dagdb_context_packets USING btree (tenant_id, namespace, request_id, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_packets_finality",
        "dagdb_context_packets USING btree (tenant_id, namespace, dag_finality_status, validation_status)",
    ),
    (
        "idx_dagdb_validation_subject",
        "dagdb_validation_reports USING btree (tenant_id, namespace, subject_kind, subject_id, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_validation_status",
        "dagdb_validation_reports USING btree (tenant_id, namespace, validation_status, risk_bp DESC)",
    ),
    (
        "idx_dagdb_safety_agent_window",
        "dagdb_agent_safety_scores USING btree (tenant_id, namespace, agent_did, window_end_physical_ms DESC, window_end_logical DESC)",
    ),
    (
        "idx_dagdb_credentials_agent",
        "dagdb_inbound_agent_credentials USING btree (tenant_id, namespace, agent_did, credential_status, expires_at_physical_ms, expires_at_logical)",
    ),
    (
        "idx_dagdb_council_subject",
        "dagdb_council_decisions USING btree (tenant_id, namespace, subject_kind, subject_id, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_council_status",
        "dagdb_council_decisions USING btree (tenant_id, namespace, decision_status, risk_class)",
    ),
    (
        "idx_dagdb_council_expiry",
        "WHERE (decision_status = ANY (ARRAY['approved'::text, 'escalated'::text]))",
    ),
    (
        "idx_dagdb_idempotency_expires",
        "dagdb_idempotency_keys USING btree (expires_at_physical_ms, expires_at_logical)",
    ),
    (
        "idx_dagdb_outbox_status_next",
        "WHERE (dag_finality_status = ANY (ARRAY['pending'::text, 'failed'::text]))",
    ),
    (
        "idx_dagdb_outbox_subject",
        "dagdb_dag_outbox USING btree (tenant_id, namespace, subject_kind, subject_id)",
    ),
    (
        "idx_dagdb_benchmark_fixture",
        "dagdb_benchmark_runs USING btree (fixture_id, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_benchmark_runner",
        "dagdb_benchmark_runs USING btree (runner_name, fixture_id, deterministic_seed)",
    ),
    (
        "idx_dagdb_exports_scope_status",
        "dagdb_exports USING btree (tenant_id, namespace, export_status, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_exports_scope_hash",
        "dagdb_exports USING btree (tenant_id, namespace, export_scope_hash, whole_export_hash)",
    ),
    (
        "idx_dagdb_export_challenges_export",
        "dagdb_export_challenges USING btree (tenant_id, namespace, export_id, challenge_kind)",
    ),
    (
        "idx_dagdb_graph_nodes_memory",
        "dagdb_graph_nodes USING btree (tenant_id, namespace, memory_id, graph_style)",
    ),
    (
        "idx_dagdb_graph_edges_from_kind",
        "dagdb_graph_edges USING btree (tenant_id, namespace, from_memory_id, edge_kind)",
    ),
    (
        "idx_dagdb_graph_edge_tombstones_edge",
        "dagdb_graph_edge_tombstones USING btree (tenant_id, namespace, prior_edge_id)",
    ),
    (
        "idx_dagdb_graph_edge_tombstones_created",
        "dagdb_graph_edge_tombstones USING btree (tenant_id, namespace, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_graph_layers_path",
        "dagdb_graph_layers USING btree (tenant_id, namespace, layer_path)",
    ),
    (
        "idx_dagdb_graph_layers_parent_layer",
        "dagdb_graph_layers USING btree (tenant_id, namespace, parent_layer_id)",
    ),
    (
        "idx_dagdb_graph_layers_parent_graph_node",
        "dagdb_graph_layers USING btree (tenant_id, namespace, parent_graph_node_id)",
    ),
    (
        "idx_dagdb_graph_layer_memberships_layer_node",
        "dagdb_graph_layer_memberships USING btree (tenant_id, namespace, layer_id, graph_node_id)",
    ),
    (
        "idx_dagdb_graph_layer_memberships_graph_node",
        "dagdb_graph_layer_memberships USING btree (tenant_id, namespace, graph_node_id, layer_id)",
    ),
    (
        "idx_dagdb_graph_layer_edges_from",
        "dagdb_graph_layer_edges USING btree (tenant_id, namespace, from_layer_id, edge_kind)",
    ),
    (
        "idx_dagdb_graph_layer_edges_to",
        "dagdb_graph_layer_edges USING btree (tenant_id, namespace, to_layer_id, edge_kind)",
    ),
    (
        "idx_dagdb_graph_layer_edges_kind",
        "dagdb_graph_layer_edges USING btree (tenant_id, namespace, edge_kind, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
    (
        "idx_dagdb_graph_similarity_candidate",
        "dagdb_graph_similarity_results USING btree (tenant_id, namespace, candidate_memory_id, similarity_bp DESC)",
    ),
    (
        "idx_dagdb_graph_canon_input",
        "dagdb_graph_canonicalization_decisions USING btree (tenant_id, namespace, input_memory_id)",
    ),
    (
        "idx_dagdb_graph_views_root_style",
        "dagdb_graph_views USING btree (tenant_id, namespace, source_root_id, graph_style, stale)",
    ),
    (
        "idx_dagdb_graph_route_invalidations_route",
        "dagdb_graph_route_invalidations USING btree (tenant_id, namespace, route_id, created_at_physical_ms DESC, created_at_logical DESC)",
    ),
];

fn final_tenant_rls_schema_sql() -> String {
    format!(
        "{DAGDB_TENANT_RLS_SCHEMA_SQL}\n{DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL}"
    )
}

fn final_operational_event_schema_sql() -> String {
    format!(
        "{DAGDB_EXPORT_SCHEMA_SQL}\n{DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL}\n{DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL}"
    )
}

#[tokio::test]
async fn schema_matches_declared_table_and_index_contract() {
    let Some(mut db) = TestDb::maybe_new("migration_contract").await else {
        return;
    };
    db.apply_schema().await;
    db.apply_schema().await;

    assert_tables(&mut db.conn).await;
    assert_required_columns(&mut db.conn).await;
    assert_constraints(&mut db.conn).await;
    assert_indexes(&mut db.conn).await;
    assert!(CATALOG_ROOT_HASH_SEMANTICS.contains("catalog material hashes"));
}

#[test]
fn rls_migration_source_enables_forced_tenant_policy_for_expected_tables() {
    let lower = final_tenant_rls_schema_sql().to_ascii_lowercase();
    let normalized_sql_literal = lower.replace("''", "'");
    assert!(lower.contains("enable row level security"));
    assert!(lower.contains("force row level security"));
    assert!(lower.contains("create or replace function dagdb_current_tenant_id()"));
    assert!(normalized_sql_literal.contains("bound_tenant_id := current_setting('exo.tenant_id')"));
    assert!(lower.contains("raise exception 'exo.tenant_id is not set'"));
    assert!(lower.contains("create policy dagdb_tenant_isolation"));
    assert!(normalized_sql_literal.contains("using (tenant_id = dagdb_current_tenant_id())"));
    assert!(normalized_sql_literal.contains("with check (tenant_id = dagdb_current_tenant_id())"));
    assert!(!normalized_sql_literal.contains("current_setting('exo.tenant_id', true)"));

    for table in EXPECTED_TENANT_RLS_TABLES {
        assert!(
            lower.contains(&format!("'{table}'")),
            "RLS migration must enumerate tenant table {table}"
        );
    }
    assert!(!lower.contains("'dagdb_benchmark_runs'"));
    assert!(!lower.contains("'dagdb_lifecycle_rollbacks'"));
    assert!(!lower.contains("'dagdb_root_bundle_receipts'"));
}

#[test]
fn pr708_additive_migration_owns_post_deploy_contract_expansion() {
    let restored_export = DAGDB_EXPORT_SCHEMA_SQL.to_ascii_lowercase();
    assert!(restored_export.contains("export_challenge_verified"));
    for event_type in OPERATIONAL_RECEIPT_EVENT_TYPES {
        assert!(
            !restored_export.contains(event_type),
            "restored applied export migration must not absorb PR #708 event type {event_type}"
        );
    }

    let restored_rls = DAGDB_TENANT_RLS_SCHEMA_SQL.to_ascii_lowercase();
    for table in PR708_NEW_TENANT_RLS_TABLES {
        assert!(
            !restored_rls.contains(&format!("'{table}'")),
            "restored applied tenant RLS migration must not absorb PR #708 table {table}"
        );
    }

    let final_event_sql = final_operational_event_schema_sql().to_ascii_lowercase();
    let additive = DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL.to_ascii_lowercase();
    for event_type in OPERATIONAL_RECEIPT_EVENT_TYPES {
        assert!(
            final_event_sql.contains(event_type),
            "final operational event contract must accept event type {event_type}"
        );
        assert!(
            additive.contains(event_type),
            "PR #708 additive migration must accept operational event type {event_type}"
        );
    }
    for table in PR708_NEW_TENANT_RLS_TABLES {
        assert!(
            additive.contains(&format!("'{table}'")),
            "PR #708 additive migration must force tenant RLS on {table}"
        );
    }
}

#[test]
fn root_bundle_receipts_are_global_immutable_schema_contract() {
    let lower = DAGDB_SCHEMA_SQL.to_ascii_lowercase();
    assert!(lower.contains("create table if not exists dagdb_root_bundle_receipts"));
    assert!(lower.contains("bundle_id bytea primary key not null"));
    assert!(lower.contains("root_bundle_hash bytea not null unique"));
    assert!(lower.contains("verification_receipt_hash bytea not null unique"));
    assert!(lower.contains("verification_receipt_body jsonb not null"));
    assert!(lower.contains("immutable boolean not null default true"));
    assert!(lower.contains("check (immutable = true)"));
    assert!(lower.contains("prevent_dagdb_root_bundle_receipt_mutation"));
    assert!(lower.contains("root_bundle_receipts_are_immutable"));
    assert!(!lower.contains("dagdb_root_bundle_receipts (\n    tenant_id"));
}

#[test]
fn node_store_tables_are_dagdb_schema_contract() {
    let lower = DAGDB_SCHEMA_SQL.to_ascii_lowercase();
    for table in [
        "dagdb_node_dag_nodes",
        "dagdb_node_dag_parents",
        "dagdb_node_committed",
        "dagdb_node_consensus_meta",
        "dagdb_node_consensus_votes",
        "dagdb_node_commit_certificates",
        "dagdb_node_validators",
        "dagdb_node_trust_receipts",
        "dagdb_node_economy_objects",
        "dagdb_node_economy_anchors",
        "dagdb_node_economy_meta",
    ] {
        assert!(
            lower.contains(&format!("create table if not exists {table}")),
            "DAG DB schema must include node-store table {table}"
        );
    }
    assert!(lower.contains("tenant_id text not null"));
    assert!(lower.contains("namespace text not null"));
    assert!(lower.contains("cbor_payload bytea not null"));
    assert!(lower.contains("receipt_hash bytea not null"));
    assert!(lower.contains("primary key (tenant_id, namespace, receipt_hash)"));
    assert!(lower.contains("anchor_hash bytea not null"));
    assert!(lower.contains("primary key (tenant_id, namespace, anchor_hash)"));
    assert!(lower.contains("idx_dagdb_node_committed_height"));
    assert!(lower.contains("idx_dagdb_node_trust_receipts_actor"));

    let rls_lower = final_tenant_rls_schema_sql().to_ascii_lowercase();
    for table in [
        "dagdb_node_dag_nodes",
        "dagdb_node_dag_parents",
        "dagdb_node_committed",
        "dagdb_node_consensus_meta",
        "dagdb_node_consensus_votes",
        "dagdb_node_commit_certificates",
        "dagdb_node_validators",
        "dagdb_node_trust_receipts",
        "dagdb_node_economy_objects",
        "dagdb_node_economy_anchors",
        "dagdb_node_economy_meta",
    ] {
        assert!(
            rls_lower.contains(&format!("'{table}'")),
            "DAG DB tenant RLS migration must enumerate node-store table {table}"
        );
    }
}

#[test]
fn zerodentity_records_are_dagdb_schema_contract() {
    let lower = DAGDB_SCHEMA_SQL.to_ascii_lowercase();
    assert!(
        lower.contains("create table if not exists dagdb_zerodentity_records"),
        "DAG DB schema must include the 0dentity durable record table"
    );
    assert!(lower.contains("state_family text not null"));
    assert!(lower.contains("subject_did text not null"));
    assert!(lower.contains("record_key text not null"));
    assert!(lower.contains("secondary_key text not null"));
    assert!(lower.contains("cbor_payload bytea not null"));
    assert!(
        lower.contains(
            "primary key (tenant_id, namespace, state_family, record_key, secondary_key)"
        )
    );
    for family in [
        "claim",
        "score",
        "previous_score",
        "score_history",
        "device_fingerprint",
        "behavioral_sample",
        "otp_challenge",
        "otp_lockout",
        "attestation",
        "identity_session",
        "session_nonce",
        "dag_node",
        "trust_receipt",
    ] {
        assert!(
            lower.contains(&format!("'{family}'")),
            "0dentity durable state family {family} must be schema-enforced"
        );
    }

    let rls_lower = final_tenant_rls_schema_sql().to_ascii_lowercase();
    assert!(
        rls_lower.contains("'dagdb_zerodentity_records'"),
        "DAG DB tenant RLS migration must enumerate 0dentity records"
    );
}

#[test]
fn gateway_state_records_are_dagdb_schema_contract() {
    let lower = DAGDB_SCHEMA_SQL.to_ascii_lowercase();
    for family in [
        "did_document",
        "session",
        "user",
        "agent",
        "decision",
        "delegation",
        "audit_entry",
        "constitution",
        "identity_score",
        "enrollment",
        "livesafe_identity",
        "scan_receipt",
        "consent_anchor",
        "trustee_shard",
        "agent_role",
        "consent_record",
        "authority_chain",
        "layout_template",
        "feedback_issue",
        "conflict_declaration",
        "avc_registry_state",
        "hlc_counter",
    ] {
        assert!(
            lower.contains(&format!("'{family}'")),
            "DAG DB schema must enumerate gateway state family {family}"
        );
    }
    assert!(
        lower.contains("create table if not exists dagdb_gateway_state_records"),
        "DAG DB schema must include the gateway durable state table"
    );
    assert!(lower.contains("state_family text not null"));
    assert!(lower.contains("record_key text not null"));
    assert!(lower.contains("cbor_payload bytea not null"));
    assert!(lower.contains("primary key (tenant_id, namespace, state_family, record_key)"));

    let rls_lower = final_tenant_rls_schema_sql().to_ascii_lowercase();
    assert!(
        rls_lower.contains("'dagdb_gateway_state_records'"),
        "DAG DB tenant RLS migration must enumerate gateway state records"
    );
}

#[tokio::test]
async fn rls_policies_fail_closed_without_tenant_context() {
    let Some(mut db) = TestDb::maybe_new("rls_contract").await else {
        return;
    };
    db.apply_schema().await;

    assert_rls_catalog_state(&mut db.conn).await;
    let rls_test_role = assume_rls_checked_role(&mut db.conn, &db.schema).await;

    let mut tx = db.conn.begin().await.expect("begin tenant-bound insert");
    bind_tenant_context(&mut tx, "tenant-a")
        .await
        .expect("bind tenant-a context");
    insert_idempotency_fixture_tx(&mut tx, "tenant-a", "idem-a")
        .await
        .expect("tenant-bound insert succeeds");
    tx.commit().await.expect("commit tenant-bound insert");

    let missing_context_count = idempotency_count_conn(&mut db.conn, "tenant-a").await;
    assert!(
        missing_context_count.is_err(),
        "read without exo.tenant_id must error instead of returning zero rows"
    );

    let missing_insert =
        insert_idempotency_fixture_conn(&mut db.conn, "tenant-a", "idem-missing").await;
    assert!(
        missing_insert.is_err(),
        "insert without exo.tenant_id must be rejected by RLS WITH CHECK"
    );

    let mut tx = db.conn.begin().await.expect("begin cross-tenant read");
    bind_tenant_context(&mut tx, "tenant-b")
        .await
        .expect("bind tenant-b context");
    let cross_tenant_count = idempotency_count_tx(&mut tx, "tenant-a")
        .await
        .expect("cross-tenant read succeeds");
    tx.commit().await.expect("commit cross-tenant read");
    assert_eq!(cross_tenant_count, 0);

    let mut tx = db.conn.begin().await.expect("begin same-tenant read");
    bind_tenant_context(&mut tx, "tenant-a")
        .await
        .expect("bind tenant-a context");
    let same_tenant_count = idempotency_count_tx(&mut tx, "tenant-a")
        .await
        .expect("same-tenant read succeeds");
    tx.commit().await.expect("commit same-tenant read");
    assert_eq!(same_tenant_count, 1);

    if let Some(role_name) = rls_test_role {
        cleanup_rls_checked_role(&mut db.conn, &role_name).await;
    }
}

#[tokio::test]
async fn migration_rollback_leaves_no_partial_schema() {
    let Some(mut db) = TestDb::maybe_new("rollback_contract").await else {
        return;
    };
    sqlx::raw_sql("BEGIN")
        .execute(&mut db.conn)
        .await
        .expect("begin migration rollback test");
    db.set_search_path().await;
    sqlx::raw_sql(DAGDB_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply DAG DB schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply DAG DB graph schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_EXPORT_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply DAG DB export schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply PRD17 default-route schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply PRD17 context-packet schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply PRD17 lifecycle schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_TENANT_RLS_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply DAG DB tenant RLS schema inside rollback transaction");
    sqlx::raw_sql(DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL)
        .execute(&mut db.conn)
        .await
        .expect("apply PR #708 operational event/RLS schema inside rollback transaction");
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut db.conn)
        .await
        .expect("rollback DAG DB schema transaction");

    let table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name LIKE 'dagdb_%'",
    )
    .bind(&db.schema)
    .fetch_one(&mut db.conn)
    .await
    .expect("count tables after rollback");
    assert_eq!(table_count, 0);
}

#[tokio::test]
async fn init_pool_runs_registered_migrations_in_clean_schema() {
    let Some(db) = TestDb::maybe_new("init_pool_contract").await else {
        return;
    };
    let scoped_url = database_url_with_search_path(&db.database_url, &db.schema);
    let pool = init_pool(&scoped_url)
        .await
        .expect("init_pool must run registered DAG DB migrations");

    let table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'dagdb_%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count tables migrated through init_pool");
    assert_eq!(
        table_count,
        i64::try_from(EXPECTED_TABLES.len()).expect("expected table count fits i64")
    );

    pool.close().await;
}

#[tokio::test]
async fn pr708_migrator_upgrades_from_last_successful_deployed_ledger() {
    let Some(db) = TestDb::maybe_new("pr708_upgrade_contract").await else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db.database_url)
        .await
        .expect("connect upgrade regression pool");
    let last_successful_migration_dir =
        create_last_successful_deployed_migration_dir("pr708_upgrade_contract");
    let last_successful_migrator = Migrator::new(last_successful_migration_dir.as_path())
        .await
        .expect("load last successful deployed DAG DB migrations");

    run_migrator_in_schema(&pool, &last_successful_migrator, &db.schema).await;
    run_migrations_in_schema(&pool, &db.schema)
        .await
        .expect("PR #708 migrator must upgrade last successful deployed ledger");

    assert_recorded_versions(&pool, &db.schema, PR708_NEW_MIGRATION_VERSIONS).await;
    assert_tables_present(&pool, &db.schema, PR708_NEW_TENANT_RLS_TABLES).await;
    assert_schema_rls_forced(&pool, &db.schema, PR708_NEW_TENANT_RLS_TABLES).await;
    assert_operational_event_types_accepted(&pool, &db.schema).await;

    pool.close().await;
    fs::remove_dir_all(&last_successful_migration_dir)
        .expect("remove last successful deployed migration test directory");
}

async fn assert_tables(conn: &mut PgConnection) {
    let mut actual = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'dagdb_%' \
         ORDER BY table_name",
    )
    .fetch_all(conn)
    .await
    .expect("query DAG DB tables");
    actual.sort();
    assert_eq!(actual, EXPECTED_TABLES);
}

async fn assert_required_columns(conn: &mut PgConnection) {
    for (table, columns) in expected_columns() {
        if columns.is_empty() {
            continue;
        }
        let actual = sqlx::query(
            "SELECT column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 \
             ORDER BY ordinal_position",
        )
        .bind(table)
        .fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("query columns for {table}: {err}"));

        let actual_names = actual
            .iter()
            .map(|row| row.get::<String, _>("column_name"))
            .collect::<Vec<_>>();
        let expected_names = columns
            .iter()
            .map(|column| column.name.to_owned())
            .collect::<Vec<_>>();
        assert_eq!(actual_names, expected_names, "column names for {table}");

        for expected in &columns {
            let row = actual
                .iter()
                .find(|row| row.get::<String, _>("column_name") == expected.name)
                .unwrap_or_else(|| panic!("missing column {}.{}", table, expected.name));
            assert_eq!(
                row.get::<String, _>("data_type"),
                expected.data_type,
                "data type for {table}.{}",
                expected.name
            );
            let nullable = row.get::<String, _>("is_nullable") == "YES";
            assert_eq!(
                nullable, expected.nullable,
                "nullability for {table}.{}",
                expected.name
            );
            if let Some(default) = expected.default_contains {
                let actual_default = row
                    .try_get::<String, _>("column_default")
                    .unwrap_or_default();
                assert!(
                    actual_default.contains(default),
                    "default for {table}.{} expected to contain {default}, got {actual_default:?}",
                    expected.name
                );
            }
        }
    }
}

async fn assert_constraints(conn: &mut PgConnection) {
    let constraints = sqlx::query(
        "SELECT rel.relname AS table_name, con.conname, con.contype, \
         pg_get_constraintdef(con.oid) AS definition \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid = con.conrelid \
         JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
         WHERE ns.nspname = current_schema() AND rel.relname LIKE 'dagdb_%'",
    )
    .fetch_all(conn)
    .await
    .expect("query constraints");
    for (table, snippet) in expected_constraint_snippets() {
        assert!(
            constraints.iter().any(|row| {
                row.get::<String, _>("table_name") == *table
                    && row.get::<String, _>("definition").contains(snippet)
            }),
            "missing constraint snippet {snippet:?} on {table}"
        );
    }
}

async fn assert_indexes(conn: &mut PgConnection) {
    let rows = sqlx::query(
        "SELECT indexname, indexdef FROM pg_indexes \
         WHERE schemaname = current_schema() AND indexname LIKE '%dagdb%'",
    )
    .fetch_all(conn)
    .await
    .expect("query indexes");
    for (index_name, expected_fragment) in EXPECTED_INDEXES {
        let indexdef = rows
            .iter()
            .find(|row| row.get::<String, _>("indexname") == *index_name)
            .map(|row| row.get::<String, _>("indexdef"))
            .unwrap_or_else(|| panic!("missing index {index_name}"));
        assert!(
            indexdef.contains(expected_fragment),
            "index {index_name} expected fragment {expected_fragment:?}, got {indexdef:?}"
        );
    }
}

async fn assert_rls_catalog_state(conn: &mut PgConnection) {
    for table in EXPECTED_TENANT_RLS_TABLES {
        let row = sqlx::query(
            "SELECT relrowsecurity, relforcerowsecurity \
             FROM pg_class rel \
             JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
             WHERE ns.nspname = current_schema() AND rel.relname = $1",
        )
        .bind(table)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("query RLS flags for {table}: {err}"));
        assert!(
            row.get::<bool, _>("relrowsecurity"),
            "{table} must enable RLS"
        );
        assert!(
            row.get::<bool, _>("relforcerowsecurity"),
            "{table} must force RLS"
        );

        let policy = sqlx::query(
            "SELECT qual, with_check FROM pg_policies \
             WHERE schemaname = current_schema() AND tablename = $1 \
               AND policyname = 'dagdb_tenant_isolation'",
        )
        .bind(table)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("query tenant RLS policy for {table}: {err}"));
        let qual = policy.get::<String, _>("qual").to_ascii_lowercase();
        let with_check = policy.get::<String, _>("with_check").to_ascii_lowercase();
        assert!(qual.contains("tenant_id = dagdb_current_tenant_id()"));
        assert!(with_check.contains("tenant_id = dagdb_current_tenant_id()"));
        assert!(!qual.contains("true"));
        assert!(!with_check.contains("true"));
    }
}

fn create_last_successful_deployed_migration_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exo_dagdb_{label}_{}", process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("remove stale last successful migration test directory");
    }
    fs::create_dir_all(&dir).expect("create last successful migration test directory");

    let source_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for filename in LAST_SUCCESSFUL_DEPLOYED_MIGRATION_FILES {
        let source = source_dir.join(filename);
        let destination = dir.join(filename);
        let copied = fs::copy(&source, &destination)
            .unwrap_or_else(|err| panic!("copy migration {filename} into test directory: {err}"));
        assert!(copied > 0, "migration {filename} must not be empty");
    }

    dir
}

async fn run_migrator_in_schema(pool: &Pool<Postgres>, migrator: &Migrator, schema: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA IF NOT EXISTS {schema}"
    )))
    .execute(pool)
    .await
    .expect("create migration test schema");
    let mut conn = pool.acquire().await.expect("acquire migration connection");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET search_path TO {schema}, public"
    )))
    .execute(&mut *conn)
    .await
    .expect("set migration search_path");
    migrator
        .run(&mut *conn)
        .await
        .expect("run test migrator in schema");
    conn.close()
        .await
        .expect("close migration-scoped connection");
}

async fn assert_recorded_versions(pool: &Pool<Postgres>, schema: &str, expected_versions: &[i64]) {
    let actual_versions: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT version FROM {schema}._sqlx_migrations ORDER BY version"
    )))
    .fetch_all(pool)
    .await
    .expect("query DAG DB migration ledger versions");
    for expected_version in expected_versions {
        assert!(
            actual_versions.contains(expected_version),
            "migration ledger must record version {expected_version}"
        );
    }
    assert_eq!(
        actual_versions.last().copied(),
        expected_versions.last().copied(),
        "PR #708 upgrade must leave the additive migration as the latest recorded DAG DB version"
    );
}

async fn assert_tables_present(pool: &Pool<Postgres>, schema: &str, tables: &[&str]) {
    for table in tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
             SELECT 1 FROM information_schema.tables \
             WHERE table_schema = $1 AND table_name = $2 \
             )",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("query presence for table {table}: {err}"));
        assert!(exists, "PR #708 upgrade must create DAG DB table {table}");
    }
}

async fn assert_schema_rls_forced(pool: &Pool<Postgres>, schema: &str, tables: &[&str]) {
    for table in tables {
        let row = sqlx::query(
            "SELECT relrowsecurity, relforcerowsecurity \
             FROM pg_class rel \
             JOIN pg_namespace ns ON ns.oid = rel.relnamespace \
             WHERE ns.nspname = $1 AND rel.relname = $2",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("query RLS state for upgraded table {table}: {err}"));
        assert!(
            row.get::<bool, _>("relrowsecurity"),
            "PR #708 upgrade must enable RLS on {table}"
        );
        assert!(
            row.get::<bool, _>("relforcerowsecurity"),
            "PR #708 upgrade must force RLS on {table}"
        );
    }
}

async fn assert_operational_event_types_accepted(pool: &Pool<Postgres>, schema: &str) {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire event insert connection");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET search_path TO {schema}, public"
    )))
    .execute(&mut *conn)
    .await
    .expect("set event insert search_path");
    let mut tx = conn.begin().await.expect("begin event insert transaction");
    bind_tenant_context(&mut tx, "tenant-pr708-upgrade")
        .await
        .expect("bind upgrade tenant context");
    for (index, event_type) in OPERATIONAL_RECEIPT_EVENT_TYPES.iter().enumerate() {
        insert_receipt_event_type_tx(&mut tx, index, event_type)
            .await
            .unwrap_or_else(|err| panic!("insert operational event type {event_type}: {err}"));
    }
    tx.commit().await.expect("commit event insert transaction");
    conn.close().await.expect("close event insert connection");
}

async fn insert_receipt_event_type_tx(
    tx: &mut Transaction<'_, Postgres>,
    index: usize,
    event_type: &str,
) -> std::result::Result<(), sqlx::Error> {
    let seed = u8::try_from(index + 1).expect("operational event fixture index fits u8");
    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, \
          receipt_body, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-pr708-upgrade', 'dag-db', 'memory', $2, $3, $4, $5, \
                 'did:exo:pr708-upgrade-regression', 1, 0, $6, $7, 1, 0)",
    )
    .bind(vec![seed; 32])
    .bind(vec![seed.saturating_add(32); 32])
    .bind(vec![seed.saturating_add(64); 32])
    .bind(i64::try_from(index + 1).expect("operational event fixture sequence fits i64"))
    .bind(event_type)
    .bind(vec![seed.saturating_add(96); 32])
    .bind(serde_json::json!({ "event_type": event_type }))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn assume_rls_checked_role(conn: &mut PgConnection, schema: &str) -> Option<String> {
    let bypasses_rls: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("query current role RLS bypass state");
    if !bypasses_rls {
        return None;
    }

    let role_name = format!("dagdb_rls_test_{}", process::id());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP ROLE IF EXISTS {role_name}"
    )))
    .execute(&mut *conn)
    .await
    .expect("drop stale RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role_name}")))
        .execute(&mut *conn)
        .await
        .expect("create RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA {schema} TO {role_name}"
    )))
    .execute(&mut *conn)
    .await
    .expect("grant schema usage to RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role_name}"
    )))
    .execute(&mut *conn)
    .await
    .expect("grant table privileges to RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT EXECUTE ON FUNCTION {schema}.dagdb_current_tenant_id() TO {role_name}"
    )))
    .execute(&mut *conn)
    .await
    .expect("grant tenant helper execution to RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SET ROLE {role_name}")))
        .execute(conn)
        .await
        .expect("switch to RLS test role");
    Some(role_name)
}

async fn cleanup_rls_checked_role(conn: &mut PgConnection, role_name: &str) {
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset RLS test role");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role_name}")))
        .execute(&mut *conn)
        .await
        .expect("drop RLS test role privileges");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP ROLE IF EXISTS {role_name}"
    )))
    .execute(conn)
    .await
    .expect("drop RLS test role");
}

async fn insert_idempotency_fixture_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    idempotency_key: &str,
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, \
          status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         VALUES ($1, 'dag-db', 'rls-test', $2, $3, $4, $5, 201, false, 1, 0, 2, 0)",
    )
    .bind(tenant_id)
    .bind(idempotency_key)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .bind(serde_json::json!({"fixture": "rls"}))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_idempotency_fixture_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    idempotency_key: &str,
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, \
          status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         VALUES ($1, 'dag-db', 'rls-test', $2, $3, $4, $5, 201, false, 1, 0, 2, 0)",
    )
    .bind(tenant_id)
    .bind(idempotency_key)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .bind(serde_json::json!({"fixture": "rls"}))
    .execute(conn)
    .await?;
    Ok(())
}

async fn idempotency_count_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = 'dag-db' AND route_name = 'rls-test'",
    )
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await
}

async fn idempotency_count_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = 'dag-db' AND route_name = 'rls-test'",
    )
    .bind(tenant_id)
    .fetch_one(conn)
    .await
}

fn expected_constraint_snippets() -> &'static [(&'static str, &'static str)] {
    &[
        ("dagdb_receipts", "octet_length(receipt_hash) = 32"),
        ("dagdb_receipts", "subject_kind = ANY"),
        ("dagdb_receipts", "dagdb_export_completed"),
        ("dagdb_root_bundle_receipts", "octet_length(bundle_id) = 32"),
        (
            "dagdb_root_bundle_receipts",
            "octet_length(root_bundle_hash) = 32",
        ),
        (
            "dagdb_root_bundle_receipts",
            "octet_length(verification_receipt_hash) = 32",
        ),
        ("dagdb_root_bundle_receipts", "immutable = true"),
        ("dagdb_memory_objects", "node_type = ANY"),
        ("dagdb_memory_objects", "source_type = ANY"),
        ("dagdb_memory_objects", "consent_purpose = ANY"),
        ("dagdb_memory_objects", "risk_bp >= 0"),
        ("dagdb_memory_edges", "edge_type = ANY"),
        ("dagdb_route_receipts", "token_budget > 0"),
        ("dagdb_validation_reports", "decision = ANY"),
        (
            "dagdb_agent_safety_scores",
            "window_end_physical_ms > window_start_physical_ms",
        ),
        ("dagdb_inbound_agent_credentials", "credential_status = ANY"),
        ("dagdb_council_decisions", "decision_source = ANY"),
        ("dagdb_idempotency_keys", "cached_failure = false"),
        ("dagdb_dag_outbox", "max_attempts = 6"),
        ("dagdb_benchmark_runs", "runner_name = ANY"),
        (
            "dagdb_exports",
            "schema_version = 'dagdb_kg_portable_export_v1'",
        ),
        ("dagdb_exports", "export_status = ANY"),
        ("dagdb_export_challenges", "challenge_kind = ANY"),
        (
            "dagdb_export_challenges",
            "proof_algorithm = 'hash_commitment_v1'",
        ),
        ("dagdb_graph_nodes", "graph_style = ANY"),
        ("dagdb_graph_nodes", "node_kind = ANY"),
        ("dagdb_graph_edges", "edge_kind = ANY"),
        ("dagdb_graph_edge_tombstones", "recommended_action = ANY"),
        ("dagdb_graph_layers", "layer_kind = ANY"),
        ("dagdb_graph_layers", "graph_style = ANY"),
        ("dagdb_graph_layers", "layer_depth >= 0"),
        ("dagdb_graph_layer_memberships", "membership_role = ANY"),
        ("dagdb_graph_layer_memberships", "local_node_rank >= 0"),
        ("dagdb_graph_layer_edges", "edge_kind = ANY"),
        ("dagdb_graph_similarity_results", "similarity_bp >= 0"),
        (
            "dagdb_graph_canonicalization_decisions",
            "decision_kind = ANY",
        ),
        ("dagdb_graph_views", "view_type = ANY"),
        ("dagdb_graph_route_invalidations", "trigger_type = ANY"),
        ("dagdb_graph_route_invalidations", "new_route_status = ANY"),
    ]
}

#[derive(Debug, Clone, Copy)]
struct ColumnExpectation {
    name: &'static str,
    data_type: &'static str,
    nullable: bool,
    default_contains: Option<&'static str>,
}

const fn col(
    name: &'static str,
    data_type: &'static str,
    nullable: bool,
    default_contains: Option<&'static str>,
) -> ColumnExpectation {
    ColumnExpectation {
        name,
        data_type,
        nullable,
        default_contains,
    }
}

fn expected_columns() -> Vec<(&'static str, Vec<ColumnExpectation>)> {
    vec![
        (
            "dagdb_receipts",
            vec![
                col("receipt_hash", "bytea", false, None),
                col("tenant_id", "text", false, None),
                col("namespace", "text", false, None),
                col("subject_kind", "text", false, None),
                col("subject_id", "bytea", false, None),
                col("prev_receipt_hash", "bytea", false, None),
                col("seq", "bigint", false, None),
                col("event_type", "text", false, None),
                col("actor_did", "text", false, None),
                col("event_hlc_physical_ms", "bigint", false, None),
                col("event_hlc_logical", "integer", false, None),
                col("event_hash", "bytea", false, None),
                col("receipt_body", "jsonb", false, None),
                col("created_at_physical_ms", "bigint", false, None),
                col("created_at_logical", "integer", false, None),
            ],
        ),
        (
            "dagdb_root_bundle_receipts",
            vec![
                col("bundle_id", "bytea", false, None),
                col("root_bundle_hash", "bytea", false, None),
                col("ceremony_id", "text", false, None),
                col("issuer_did", "text", false, None),
                col("issuer_public_key_hash", "bytea", false, None),
                col("signing_set_hash", "bytea", false, None),
                col("quorum_threshold", "integer", false, None),
                col("verifier_version", "text", false, None),
                col("verification_receipt_hash", "bytea", false, None),
                col("verification_receipt_body", "jsonb", false, None),
                col("verified_at_physical_ms", "bigint", false, None),
                col("verified_at_logical", "integer", false, None),
                col("created_at_physical_ms", "bigint", false, None),
                col("created_at_logical", "integer", false, None),
                col("immutable", "boolean", false, Some("true")),
            ],
        ),
        (
            "dagdb_memory_objects",
            vec![
                col("memory_id", "bytea", false, None),
                col("tenant_id", "text", false, None),
                col("namespace", "text", false, None),
                col("node_type", "text", false, None),
                col("source_type", "text", false, None),
                col("consent_purpose", "text", false, None),
                col("payload_hash", "bytea", false, None),
                col("source_hash", "bytea", false, None),
                col("payload_uri_hash", "bytea", true, None),
                col("owner_did", "text", false, None),
                col("controller_did", "text", false, None),
                col("submitted_by_did", "text", false, None),
                col("access_policy_hash", "bytea", true, None),
                col("declared_rights_hash", "bytea", true, None),
                col("title", "jsonb", false, None),
                col("summary", "jsonb", false, None),
                col("keywords", "jsonb", false, Some("'[]'::jsonb")),
                col("risk_class", "text", false, None),
                col("risk_bp", "integer", false, None),
                col("status", "text", false, Some("'pending'::text")),
                col("validation_status", "text", false, Some("'pending'::text")),
                col(
                    "council_status",
                    "text",
                    false,
                    Some("'not_required'::text"),
                ),
                col(
                    "dag_finality_status",
                    "text",
                    false,
                    Some("'pending'::text"),
                ),
                col("latest_receipt_hash", "bytea", false, None),
                col("created_at_physical_ms", "bigint", false, None),
                col("created_at_logical", "integer", false, None),
                col("updated_at_physical_ms", "bigint", false, None),
                col("updated_at_logical", "integer", false, None),
                col("revoked_at_physical_ms", "bigint", true, None),
                col("revoked_at_logical", "integer", true, None),
                col("superseded_by_memory_id", "bytea", true, None),
                // PRD-D3 (D3-S1): nullable deep-detail-summary tier, appended by
                // the strictly-additive migration (highest ordinal position).
                col("deep_detail_summary", "jsonb", true, None),
            ],
        ),
        (
            "dagdb_inbound_agent_credentials",
            vec![
                col("credential_id", "bytea", false, None),
                col("tenant_id", "text", false, None),
                col("namespace", "text", false, None),
                col("agent_did", "text", false, None),
                col("operator_did", "text", false, None),
                col("model_name", "text", false, None),
                col("model_version", "text", false, None),
                col("provider_or_builder", "text", false, None),
                col("requested_action", "text", false, None),
                col("requested_scope_hash", "bytea", false, None),
                col("purpose", "text", false, None),
                col("autonomy_level", "text", false, None),
                col("nonce", "text", false, None),
                col("expires_at_physical_ms", "bigint", false, None),
                col("expires_at_logical", "integer", false, None),
                col("signature_hash", "bytea", false, None),
                col("credential_status", "text", false, Some("'pending'::text")),
                col("checkpoint_hash", "bytea", true, None),
                col("attestation_hash", "bytea", true, None),
                col("prior_trust_receipt_hash", "bytea", true, None),
                col("created_at_physical_ms", "bigint", false, None),
                col("created_at_logical", "integer", false, None),
            ],
        ),
        ("dagdb_subject_receipt_heads", Vec::new()),
        ("dagdb_memory_edges", Vec::new()),
        ("dagdb_catalog_entries", Vec::new()),
        ("dagdb_route_receipts", Vec::new()),
        ("dagdb_context_packets", Vec::new()),
        ("dagdb_validation_reports", Vec::new()),
        ("dagdb_agent_safety_scores", Vec::new()),
        ("dagdb_council_decisions", Vec::new()),
        ("dagdb_idempotency_keys", Vec::new()),
        ("dagdb_dag_outbox", Vec::new()),
        ("dagdb_benchmark_runs", Vec::new()),
        ("dagdb_exports", Vec::new()),
        ("dagdb_export_challenges", Vec::new()),
        ("dagdb_graph_nodes", Vec::new()),
        ("dagdb_graph_edges", Vec::new()),
        ("dagdb_graph_edge_tombstones", Vec::new()),
        ("dagdb_graph_layer_edges", Vec::new()),
        ("dagdb_graph_layer_memberships", Vec::new()),
        ("dagdb_graph_layers", Vec::new()),
        ("dagdb_graph_similarity_results", Vec::new()),
        ("dagdb_graph_canonicalization_decisions", Vec::new()),
        ("dagdb_graph_views", Vec::new()),
        ("dagdb_graph_placement_traces", Vec::new()),
        ("dagdb_graph_route_invalidations", Vec::new()),
    ]
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

struct TestDb {
    conn: PgConnection,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!("skipping migration postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut conn = PgConnection::connect(database_url.as_str())
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut conn)
        .await
        .expect("drop existing test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut conn)
            .await
            .expect("create test schema");
        let mut db = Self {
            conn,
            schema,
            database_url,
        };
        db.set_search_path().await;
        Some(db)
    }

    async fn set_search_path(&mut self) {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "SET search_path TO {}, public",
            self.schema
        )))
        .execute(&mut self.conn)
        .await
        .expect("set DAG DB test search_path");
    }

    async fn apply_schema(&mut self) {
        self.set_search_path().await;
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply DAG DB schema");
        sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply DAG DB graph schema");
        sqlx::raw_sql(DAGDB_EXPORT_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply DAG DB export schema");
        sqlx::raw_sql(DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply PRD17 default-route schema");
        sqlx::raw_sql(DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply PRD17 context-packet schema");
        sqlx::raw_sql(DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply PRD17 lifecycle schema");
        sqlx::raw_sql(DAGDB_TENANT_RLS_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply DAG DB tenant RLS schema");
        sqlx::raw_sql(DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL)
            .execute(&mut self.conn)
            .await
            .expect("apply PR #708 operational event/RLS schema");
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let schema = self.schema.clone();
        let database_url = self.database_url.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("create cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop DAG DB test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}
