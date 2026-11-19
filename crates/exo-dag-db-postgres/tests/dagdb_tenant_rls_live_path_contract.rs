#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic)]

use std::{collections::BTreeSet, process, str::FromStr};

use exo_dag_db_postgres::postgres::{
    DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
    DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL,
    DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL, DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL,
    DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL, DAGDB_SCHEMA_SQL, DAGDB_TENANT_RLS_SCHEMA_SQL,
    begin_tenant_transaction,
};
use serde_json::json;
use sqlx::{
    Connection, PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

const TEST_DATABASE_URL_ENV: &str = "EXO_DAGDB_TEST_DATABASE_URL";
const CI_DATABASE_URL_ENV: &str = "DATABASE_URL";
const RLS_TEST_ROLE_PASSWORD: &str = "dagdb_rls_live_path_password";

struct TenantTable {
    name: &'static str,
    families: &'static [&'static str],
    expected_tenant_a_rows: i64,
}

const FAMILY_EXPORT: &str = "export";
const FAMILY_IDEMPOTENCY: &str = "idempotency";
const FAMILY_IMPORT: &str = "import";
const FAMILY_LOOKUP: &str = "lookup";
const FAMILY_NODE_STORE: &str = "node_store";
const FAMILY_ZERODENTITY: &str = "zerodentity";
const FAMILY_GATEWAY_STATE: &str = "gateway_state";

const EXPORT_TABLES: &[&str] = &[
    "dagdb_exports",
    "dagdb_export_challenges",
    "dagdb_graph_similarity_results",
    "dagdb_graph_canonicalization_decisions",
    "dagdb_graph_placement_traces",
    "dagdb_graph_route_invalidations",
];
const IDEMPOTENCY_TABLES: &[&str] = &[
    "dagdb_idempotency_keys",
    "dagdb_context_packet_records",
    "dagdb_lifecycle_actions",
    "dagdb_route_invalidation_events",
    "dagdb_continuation_records",
    "dagdb_graph_edge_tombstones",
];
const IMPORT_TABLES: &[&str] = &[
    "dagdb_memory_objects",
    "dagdb_memory_edges",
    "dagdb_graph_nodes",
    "dagdb_graph_edges",
    "dagdb_graph_similarity_results",
    "dagdb_graph_canonicalization_decisions",
    "dagdb_graph_placement_traces",
    "dagdb_graph_layers",
    "dagdb_graph_layer_memberships",
    "dagdb_graph_layer_edges",
];
const LOOKUP_TABLES: &[&str] = &[
    "dagdb_receipts",
    "dagdb_subject_receipt_heads",
    "dagdb_memory_objects",
    "dagdb_memory_edges",
    "dagdb_catalog_entries",
    "dagdb_route_receipts",
    "dagdb_context_packets",
    "dagdb_validation_reports",
    "dagdb_agent_safety_scores",
    "dagdb_inbound_agent_credentials",
    "dagdb_council_decisions",
    "dagdb_graph_nodes",
    "dagdb_graph_edges",
    "dagdb_graph_views",
    "dagdb_graph_route_invalidations",
    "dagdb_graph_edge_tombstones",
    "dagdb_graph_layers",
    "dagdb_graph_layer_memberships",
    "dagdb_graph_layer_edges",
    "dagdb_default_routes",
    "dagdb_context_packet_records",
    "dagdb_lifecycle_actions",
    "dagdb_route_invalidation_events",
    "dagdb_continuation_records",
];
const REQUIRED_TABLE_FAMILIES: &[(&str, &[&str])] = &[
    (FAMILY_EXPORT, EXPORT_TABLES),
    (FAMILY_IDEMPOTENCY, IDEMPOTENCY_TABLES),
    (FAMILY_IMPORT, IMPORT_TABLES),
    (FAMILY_LOOKUP, LOOKUP_TABLES),
];

const TENANT_TABLES: &[TenantTable] = &[
    TenantTable {
        name: "dagdb_receipts",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_subject_receipt_heads",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_memory_objects",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 2,
    },
    TenantTable {
        name: "dagdb_memory_edges",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_catalog_entries",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_route_receipts",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_context_packets",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_validation_reports",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_agent_safety_scores",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_inbound_agent_credentials",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_council_decisions",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_idempotency_keys",
        families: &[FAMILY_IDEMPOTENCY],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_dag_outbox",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_nodes",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_edges",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_similarity_results",
        families: &[FAMILY_EXPORT, FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_canonicalization_decisions",
        families: &[FAMILY_EXPORT, FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_views",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_placement_traces",
        families: &[FAMILY_EXPORT, FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_route_invalidations",
        families: &[FAMILY_EXPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_edge_tombstones",
        families: &[FAMILY_IDEMPOTENCY, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_layers",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 2,
    },
    TenantTable {
        name: "dagdb_graph_layer_memberships",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_graph_layer_edges",
        families: &[FAMILY_IMPORT, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_exports",
        families: &[FAMILY_EXPORT],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_export_challenges",
        families: &[FAMILY_EXPORT],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_default_routes",
        families: &[FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_context_packet_records",
        families: &[FAMILY_IDEMPOTENCY, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_lifecycle_actions",
        families: &[FAMILY_IDEMPOTENCY, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_route_invalidation_events",
        families: &[FAMILY_IDEMPOTENCY, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_continuation_records",
        families: &[FAMILY_IDEMPOTENCY, FAMILY_LOOKUP],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_dag_nodes",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 2,
    },
    TenantTable {
        name: "dagdb_node_dag_parents",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_committed",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_consensus_meta",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_consensus_votes",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_commit_certificates",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_validators",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_trust_receipts",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_economy_objects",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_economy_anchors",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_node_economy_meta",
        families: &[FAMILY_NODE_STORE],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_zerodentity_records",
        families: &[FAMILY_ZERODENTITY],
        expected_tenant_a_rows: 1,
    },
    TenantTable {
        name: "dagdb_gateway_state_records",
        families: &[FAMILY_GATEWAY_STATE],
        expected_tenant_a_rows: 1,
    },
];

#[test]
fn rls_migration_tenant_table_list_matches_test_metadata() {
    let migration_tables = rls_migration_tenant_tables();
    let tested_tables = tested_tenant_tables();
    let missing: Vec<_> = migration_tables
        .difference(&tested_tables)
        .copied()
        .collect();
    let extra: Vec<_> = tested_tables
        .difference(&migration_tables)
        .copied()
        .collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "RLS contract metadata must match migration tenant tables; missing from tests: \
         {missing:?}; extra in tests: {extra:?}"
    );
}

#[test]
fn rls_contract_covers_import_export_lookup_and_idempotency_table_families() {
    for (family, required_tables) in REQUIRED_TABLE_FAMILIES {
        let covered_tables: BTreeSet<_> = TENANT_TABLES
            .iter()
            .filter(|table| table.families.contains(family))
            .map(|table| table.name)
            .collect();
        let missing: Vec<_> = required_tables
            .iter()
            .copied()
            .filter(|table| !covered_tables.contains(table))
            .collect();

        assert!(
            missing.is_empty(),
            "RLS contract family {family} is missing tenant tables: {missing:?}"
        );
    }
}

#[tokio::test]
async fn rls_requires_bound_tenant_context_for_live_path_tables() {
    let Some(db) = TestDb::maybe_new("rls_live_missing_context").await else {
        return;
    };
    apply_live_path_schema(&db.pool).await;
    let rls_pool = RlsCheckedPool::new(&db, "missing_context").await;
    seed_live_path_rows(&rls_pool.pool, "tenant-a")
        .await
        .expect("seed tenant rows through tenant-bound transaction");

    for table in TENANT_TABLES {
        let query = format!("SELECT count(*) FROM {}", table.name);
        let result = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&query[..]))
            .fetch_one(&rls_pool.pool)
            .await;
        assert!(
            result.is_err(),
            "unbound tenant context must fail closed for {} ({:?})",
            table.name,
            table.families
        );
    }

    rls_pool.cleanup(&db.pool).await;
}

#[tokio::test]
async fn rls_blocks_cross_tenant_reads_and_writes_for_live_path_tables() {
    let Some(db) = TestDb::maybe_new("rls_live_cross_tenant").await else {
        return;
    };
    apply_live_path_schema(&db.pool).await;
    let rls_pool = RlsCheckedPool::new(&db, "cross_tenant").await;
    seed_live_path_rows(&rls_pool.pool, "tenant-a")
        .await
        .expect("seed tenant rows through tenant-bound transaction");

    for table in TENANT_TABLES {
        let mut tenant_a_tx = begin_tenant_transaction(&rls_pool.pool, "tenant-a")
            .await
            .expect("begin tenant-a transaction");
        let tenant_a_count = count_tenant_rows(&mut tenant_a_tx, table.name, "tenant-a").await;
        tenant_a_tx
            .commit()
            .await
            .expect("commit tenant-a visibility check");
        assert_eq!(
            tenant_a_count, table.expected_tenant_a_rows,
            "tenant-a must see its own seeded rows for {}",
            table.name
        );

        let mut tenant_b_tx = begin_tenant_transaction(&rls_pool.pool, "tenant-b")
            .await
            .expect("begin tenant-b transaction");
        let tenant_b_read_count = count_tenant_rows(&mut tenant_b_tx, table.name, "tenant-a").await;
        assert_eq!(
            tenant_b_read_count, 0,
            "tenant-b must not read tenant-a rows for {}",
            table.name
        );
        let update_query = format!(
            "UPDATE {} SET tenant_id = tenant_id WHERE tenant_id = 'tenant-a'",
            table.name
        );
        let updated = sqlx::query(sqlx::AssertSqlSafe(&update_query[..]))
            .execute(&mut *tenant_b_tx)
            .await
            .expect("cross-tenant update is filtered by RLS")
            .rows_affected();
        let delete_query = format!("DELETE FROM {} WHERE tenant_id = 'tenant-a'", table.name);
        let deleted = sqlx::query(sqlx::AssertSqlSafe(&delete_query[..]))
            .execute(&mut *tenant_b_tx)
            .await
            .expect("cross-tenant delete is filtered by RLS")
            .rows_affected();
        tenant_b_tx
            .commit()
            .await
            .expect("commit tenant-b isolation check");
        assert_eq!(
            updated, 0,
            "tenant-b must not update tenant-a rows for {}",
            table.name
        );
        assert_eq!(
            deleted, 0,
            "tenant-b must not delete tenant-a rows for {}",
            table.name
        );
    }

    assert_tenant_mismatch_insert_is_rejected(&rls_pool.pool).await;
    rls_pool.cleanup(&db.pool).await;
}

fn rls_migration_tenant_tables() -> BTreeSet<&'static str> {
    rls_migration_sources()
        .into_iter()
        .flat_map(|migration_sql| migration_sql.lines().filter_map(tenant_table_from_rls_line))
        .collect()
}

fn rls_migration_sources() -> [&'static str; 2] {
    [
        DAGDB_TENANT_RLS_SCHEMA_SQL,
        DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL,
    ]
}

fn tenant_table_from_rls_line(line: &'static str) -> Option<&'static str> {
    let table = line.trim().trim_end_matches(',');
    table
        .strip_prefix('\'')
        .and_then(|table| table.strip_suffix('\''))
        .filter(|table| table.starts_with("dagdb_"))
}

fn tested_tenant_tables() -> BTreeSet<&'static str> {
    TENANT_TABLES.iter().map(|table| table.name).collect()
}

async fn count_tenant_rows(
    tx: &mut Transaction<'_, Postgres>,
    table_name: &str,
    tenant_id: &str,
) -> i64 {
    let query = format!("SELECT count(*) FROM {table_name} WHERE tenant_id = $1");
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&query[..]))
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
        .expect("count tenant rows")
}

async fn assert_tenant_mismatch_insert_is_rejected(pool: &PgPool) {
    let mut tx = begin_tenant_transaction(pool, "tenant-b")
        .await
        .expect("begin tenant-b mismatch insert transaction");
    let result = sqlx::query(
        "INSERT INTO dagdb_default_routes \
         (tenant_id, project_id, memory_namespace, route_id, status, route_source, policy_ref, \
          freshness_ref, policy_allowed, freshness_status, invalidated, \
          production_default_route_approval_status, packet_quality_review_status, \
          selected_memory_refs, selected_memory_ref_count, created_at, updated_at) \
         VALUES ('tenant-a', 'project-rls', 'default', 'route-mismatch', 'active', 'persisted', \
                 'policy-rls', 'freshness-rls', true, 'current', false, 'approved', 'approved', \
                 '[]'::jsonb, 0, '2026-06-19T00:00:00Z', '2026-06-19T00:00:00Z')",
    )
    .execute(&mut *tx)
    .await;
    assert!(
        result.is_err(),
        "WITH CHECK must reject inserting tenant-a rows while bound as tenant-b"
    );
}

async fn seed_live_path_rows(pool: &PgPool, tenant_id: &str) -> sqlx::Result<()> {
    let mut tx = begin_tenant_transaction(pool, tenant_id).await?;
    let empty_refs = json!([]);
    let empty_object = json!({});
    let safe_text = json!({
        "decision": "allow",
        "text": "safe",
        "redaction_codes": [],
        "original_hash": "caac13844969e521bb8bfcf8bc706ad54bcce3e3f260368eda31bdb0542d00e1",
        "truncated": false,
        "byte_len": 4
    });

    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, \
          receipt_body, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', 'memory', $3, $4, 1, 'intake_created', 'did:exo:rls', \
                 1, 0, $5, $6, 1, 0)",
    )
    .bind(hb(0x01))
    .bind(tenant_id)
    .bind(hb(0x21))
    .bind(vec![0_u8; 32])
    .bind(hb(0x31))
    .bind(json!({"event": "intake_created"}))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'default', 'memory', $2, $3, 1, 1, 0)",
    )
    .bind(tenant_id)
    .bind(hb(0x21))
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    for (memory_id, payload_hash, source_hash) in [(0x40, 0x41, 0x42), (0x43, 0x44, 0x45)] {
        sqlx::query(
            "INSERT INTO dagdb_memory_objects \
             (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, \
              payload_hash, source_hash, owner_did, controller_did, submitted_by_did, title, \
              summary, keywords, risk_class, risk_bp, status, validation_status, council_status, \
              latest_receipt_hash, created_at_physical_ms, created_at_logical, \
              updated_at_physical_ms, updated_at_logical) \
             VALUES ($1, $2, 'default', 'source', 'public_web', 'retrieval', $3, $4, \
                     'did:example:owner', 'did:example:controller', 'did:example:submitter', \
                     $5, $5, $6, 'R0', 0, 'routable', 'passed', 'not_required', $7, 1, 0, 1, 0)",
        )
        .bind(hb(memory_id))
        .bind(tenant_id)
        .bind(hb(payload_hash))
        .bind(hb(source_hash))
        .bind(&safe_text)
        .bind(&empty_refs)
        .bind(hb(0x01))
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO dagdb_memory_edges \
         (tenant_id, namespace, from_memory_id, to_memory_id, edge_type, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'default', $2, $3, 'cites', 1, 0)",
    )
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x43))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_catalog_entries \
         (catalog_id, tenant_id, namespace, memory_id, catalog_level, title, summary, keywords, \
          payload_hash, source_hash, status, validation_status, council_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', $3, 0, $4, $4, $5, $6, $7, 'routable', 'passed', \
                 'not_required', $8, 1, 0, 1, 0)",
    )
    .bind(hb(0x50))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(&safe_text)
    .bind(&empty_refs)
    .bind(hb(0x51))
    .bind(hb(0x52))
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_route_receipts \
         (route_id, tenant_id, namespace, requesting_agent_did, task_signature_hash, \
          approved_scope_hash, candidate_memory_ids, selected_memory_ids, route_score_bp, \
          token_budget, token_estimate, risk_bp, status, validation_status, council_status, \
          stale_at_physical_ms, stale_at_logical, latest_receipt_hash, created_at_physical_ms, \
          created_at_logical) \
         VALUES ($1, $2, 'default', 'did:example:agent', $3, $4, $5, $5, 9000, 4096, 256, \
                 0, 'active', 'passed', 'not_required', 90, 0, $6, 1, 0)",
    )
    .bind(hb(0x60))
    .bind(tenant_id)
    .bind(hb(0x61))
    .bind(hb(0x62))
    .bind(&empty_refs)
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_context_packets \
         (context_packet_id, tenant_id, namespace, request_id, route_id, task_hash, \
          requesting_agent_did, memory_refs, packet_hash, token_budget, token_estimate, \
          validation_status, council_status, latest_receipt_hash, created_at_physical_ms, \
          created_at_logical) \
         VALUES ($1, $2, 'default', 'request-rls', $3, $4, 'did:example:agent', $5, $6, \
                 4096, 256, 'passed', 'not_required', $7, 1, 0)",
    )
    .bind(hb(0x70))
    .bind(tenant_id)
    .bind(hb(0x60))
    .bind(hb(0x71))
    .bind(&empty_refs)
    .bind(hb(0x72))
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_validation_reports \
         (validation_report_id, tenant_id, namespace, subject_kind, subject_id, validator_did, \
          input_hash, policy_hash, validation_status, risk_class, risk_bp, decision, notes, \
          contradictory_report_ids, latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', 'memory', $3, 'did:example:validator', $4, $5, 'passed', \
                 'R0', 0, 'allow', $6, $7, $8, 1, 0)",
    )
    .bind(hb(0x80))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x81))
    .bind(hb(0x82))
    .bind(&safe_text)
    .bind(&empty_refs)
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_agent_safety_scores \
         (safety_score_id, tenant_id, namespace, agent_did, operator_did, \
          window_start_physical_ms, window_start_logical, window_end_physical_ms, \
          window_end_logical, evidence_hash, identity_bp, authority_bp, consent_bp, \
          provenance_bp, validation_bp, recency_bp, revocation_bp, route_quality_bp, \
          incident_penalty_bp, total_score_bp, validation_status, council_status, \
          latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', 'did:example:agent', 'did:example:operator', \
                 1, 0, 2, 0, $3, 10000, 10000, 10000, 10000, 10000, 10000, 10000, \
                 10000, 0, 10000, 'passed', 'not_required', $4, 1, 0)",
    )
    .bind(hb(0x83))
    .bind(tenant_id)
    .bind(hb(0x84))
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_inbound_agent_credentials \
         (credential_id, tenant_id, namespace, agent_did, operator_did, model_name, \
          model_version, provider_or_builder, requested_action, requested_scope_hash, \
          purpose, autonomy_level, nonce, expires_at_physical_ms, expires_at_logical, \
          signature_hash, credential_status, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', 'did:example:agent', 'did:example:operator', \
                 'model-rls', '1', 'provider-rls', 'route', $3, 'retrieval', \
                 'operator_approved', 'nonce-rls', 2, 0, $4, 'active', 1, 0)",
    )
    .bind(hb(0x85))
    .bind(tenant_id)
    .bind(hb(0x86))
    .bind(hb(0x87))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_council_decisions \
         (decision_id, tenant_id, namespace, subject_kind, subject_id, requested_action, \
          approved_scope_hash, risk_class, approver_did, decision_source, decision_status, \
          reason_code, validation_report_id, route_id, context_packet_id, notes, \
          created_at_physical_ms, created_at_logical, expires_at_physical_ms, \
          expires_at_logical, receipt_hash) \
         VALUES ($1, $2, 'default', 'memory', $3, 'route', $4, 'R0', \
                 'did:example:approver', 'policy', 'approved', 'seeded_rls_contract', \
                 $5, $6, $7, $8, 1, 0, 2, 0, $9)",
    )
    .bind(hb(0x88))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x89))
    .bind(hb(0x80))
    .bind(hb(0x60))
    .bind(hb(0x70))
    .bind(json!({"decision": "approved"}))
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, \
          response_body, status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         VALUES ($1, 'default', 'dagdb:import', 'idempotency-rls', $2, $3, $4, 201, false, 1, 0, 2, 0)",
    )
    .bind(tenant_id)
    .bind(hb(0x90))
    .bind(hb(0x91))
    .bind(json!({"status": "created"}))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_dag_outbox \
         (outbox_id, tenant_id, namespace, subject_kind, subject_id, dag_write_id, \
          dag_payload_hash, dag_finality_status, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', 'memory', $3, 'dag-write-rls', $4, 'pending', 1, 0, 1, 0)",
    )
    .bind(hb(0x95))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x96))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_nodes \
         (graph_node_id, tenant_id, namespace, memory_id, graph_style, node_kind, metadata, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', $3, 'canonical_memory_graph', 'canonical', $4, 1, 0)",
    )
    .bind(hb(0xa0))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_edges \
         (graph_edge_id, tenant_id, namespace, graph_style, from_memory_id, to_memory_id, \
          edge_kind, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', 'canonical_memory_graph', $3, $4, 'related_to', 1, 0)",
    )
    .bind(hb(0xa1))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x43))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_similarity_results \
         (similarity_result_id, tenant_id, namespace, candidate_memory_id, matched_memory_id, \
          similarity_type, similarity_bp, matched_fields, reason, created_at_physical_ms, \
          created_at_logical) \
         VALUES ($1, $2, 'default', $3, $4, 'near_duplicate', 8500, $5, \
                 'seeded similarity', 1, 0)",
    )
    .bind(hb(0xa4))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x43))
    .bind(&empty_refs)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_canonicalization_decisions \
         (decision_id, tenant_id, namespace, input_memory_id, canonical_memory_id, \
          matched_memory_ids, decision_kind, decision_reason, confidence_bp, risk_class, \
          validator_status, required_edges_to_create, receipt_hash, receipt_intent, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', $3, $4, $5, 'near_duplicate', \
                 'seeded canonicalization', 9000, 'R0', 'passed', $5, $6, \
                 'canonicalized', 1, 0)",
    )
    .bind(hb(0xa5))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0x43))
    .bind(&empty_refs)
    .bind(hb(0x01))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_views \
         (view_id, tenant_id, namespace, graph_style, source_root_id, included_node_ids, \
          included_edge_ids, view_type, topological_order, transitive_reduction_edges, \
          omitted_edges, reason_edges_omitted, source_records_hash, stale, \
          created_at_physical_ms, created_at_logical, refreshed_at_physical_ms, \
          refreshed_at_logical) \
         VALUES ($1, $2, 'default', 'canonical_memory_graph', $3, $4, $4, \
                 'canonical_view', $4, $4, $4, $4, $5, false, 1, 0, 1, 0)",
    )
    .bind(hb(0xa6))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(&empty_refs)
    .bind(hb(0xa7))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_placement_traces \
         (placement_trace_id, tenant_id, namespace, input_memory_id, trace_steps, \
          completed, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', $3, $4, true, 1, 0)",
    )
    .bind(hb(0xa8))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(&empty_refs)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_route_invalidations \
         (invalidation_id, tenant_id, namespace, route_id, affected_memory_ids, trigger_type, \
          triggering_receipt_id, prior_route_status, new_route_status, invalidation_reason, \
          created_at_physical_ms, created_at_logical, validator_id, validation_report_id, \
          receipt_hash, receipt_intent) \
         VALUES ($1, $2, 'default', $3, $4, 'risk_changed', $5, 'active', 'stale', \
                 'seeded route invalidation', 1, 0, 'did:example:validator', $6, $5, \
                 'route_invalidated')",
    )
    .bind(hb(0xa9))
    .bind(tenant_id)
    .bind(hb(0x60))
    .bind(&empty_refs)
    .bind(hb(0x01))
    .bind(hb(0x80))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_edge_tombstones \
         (tombstone_id, tenant_id, namespace, prior_edge_id, tombstone_reason, \
          recommended_action, receipt_hash, idempotency_key, created_at_physical_ms, \
          created_at_logical, tombstone_body) \
         VALUES ($1, $2, 'default', $3, 'seeded tombstone', 'review', $4, \
                 'graph-edge-tombstone-rls', 1, 0, $5)",
    )
    .bind(hb(0xaa))
    .bind(tenant_id)
    .bind(hb(0xa1))
    .bind(hb(0x01))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_layers \
         (layer_id, tenant_id, namespace, root_memory_id, layer_depth, layer_kind, graph_style, \
          layer_path, metadata, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', $3, 0, 'root', 'canonical_memory_graph', 'root', $4, 1, 0, 1, 0)",
    )
    .bind(hb(0xa2))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_layers \
         (layer_id, tenant_id, namespace, root_memory_id, parent_layer_id, parent_graph_node_id, \
          layer_depth, layer_kind, graph_style, layer_path, metadata, created_at_physical_ms, \
          created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', $3, $4, $5, 1, 'task_subgraph', \
                 'canonical_memory_graph', 'root/task', $6, 1, 0, 1, 0)",
    )
    .bind(hb(0xa3))
    .bind(tenant_id)
    .bind(hb(0x40))
    .bind(hb(0xa2))
    .bind(hb(0xa0))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_layer_memberships \
         (layer_membership_id, tenant_id, namespace, layer_id, graph_node_id, graph_style, \
          membership_role, local_node_rank, metadata, created_at_physical_ms, \
          created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', $3, $4, 'canonical_memory_graph', 'root', 0, \
                 $5, 1, 0, 1, 0)",
    )
    .bind(hb(0xab))
    .bind(tenant_id)
    .bind(hb(0xa2))
    .bind(hb(0xa0))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_graph_layer_edges \
         (layer_edge_id, tenant_id, namespace, graph_style, from_layer_id, to_layer_id, \
          edge_kind, receipt_hash, metadata, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', 'canonical_memory_graph', $3, $4, 'drills_down_to', \
                 $5, $6, 1, 0, 1, 0)",
    )
    .bind(hb(0xac))
    .bind(tenant_id)
    .bind(hb(0xa2))
    .bind(hb(0xa3))
    .bind(hb(0x01))
    .bind(&empty_object)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_exports \
         (export_id, tenant_id, namespace, schema_version, export_scope_hash, included_memory_ids_hash, \
          included_receipt_heads_hash, section_hashes, section_counts, citation_index_hash, \
          provenance_index_hash, redaction_summary_hash, omission_summary_hash, verification_hash, \
          whole_export_hash, export_status, requester_did, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'default', 'dagdb_kg_portable_export_v1', $3, $4, $5, $6, $6, $7, $8, \
                 $9, $10, $11, $12, 'verified', 'did:example:requester', 1, 0, 1, 0)",
    )
    .bind(hb(0xb0))
    .bind(tenant_id)
    .bind(hb(0xb1))
    .bind(hb(0xb2))
    .bind(hb(0xb3))
    .bind(&empty_object)
    .bind(hb(0xb4))
    .bind(hb(0xb5))
    .bind(hb(0xb6))
    .bind(hb(0xb7))
    .bind(hb(0xb8))
    .bind(hb(0xb9))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_export_challenges \
         (challenge_id, tenant_id, namespace, export_id, challenge_kind, challenge_hash, \
          proof_hash, proof_algorithm, verifier_did, verification_status, \
          verification_notes_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, 'default', $3, 'whole_export_hash', $4, $5, \
                 'hash_commitment_v1', 'did:example:verifier', 'verified', $6, 1, 0)",
    )
    .bind(hb(0xba))
    .bind(tenant_id)
    .bind(hb(0xb0))
    .bind(hb(0xbb))
    .bind(hb(0xbc))
    .bind(hb(0xbd))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_default_routes \
         (tenant_id, project_id, memory_namespace, route_id, status, route_source, policy_ref, \
          freshness_ref, policy_allowed, freshness_status, invalidated, \
          production_default_route_approval_status, packet_quality_review_status, selected_memory_refs, \
          selected_memory_ref_count, created_at, updated_at) \
         VALUES ($1, 'project-rls', 'default', 'route-rls', 'active', 'persisted', 'policy-rls', \
                 'freshness-rls', true, 'current', false, 'approved', 'approved', $2, 0, \
                 '2026-06-19T00:00:00Z', '2026-06-19T00:00:00Z')",
    )
    .bind(tenant_id)
    .bind(&empty_refs)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_context_packet_records \
         (packet_id, route_id, query_hash, tenant_id, project_id, memory_namespace, selected_memory_ids, \
          selected_edge_ids, token_budget, token_estimate, context_quality, citation_coverage_bp, \
          validation_coverage_bp, freshness_status, validation_status, source_proof_refs, \
          idempotency_key, persistence_status, production_default_route_approval_status, \
          packet_quality_review_status, created_at) \
         VALUES ('packet-rls', 'route-rls', 'query-rls', $1, 'project-rls', 'default', $2, $2, \
                 4096, 256, 'usable_context', 10000, 10000, 'current', 'passed', $2, \
                 'packet-idempotency-rls', 'persisted', 'approved', 'approved', \
                 '2026-06-19T00:00:00Z')",
    )
    .bind(tenant_id)
    .bind(&empty_refs)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_lifecycle_rollbacks \
         (rollback_id, action_id, inverse_action_type, before_refs, after_refs, validation_ref, \
          operator_required, rollback_body) \
         VALUES ('rollback-rls', 'action-rls', 'writeback', $1, $1, 'validation-rls', false, $2)",
    )
    .bind(&empty_refs)
    .bind(json!({"rollback": "noop"}))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_lifecycle_actions \
         (action_id, action_type, tenant_id, project_id, memory_namespace, actor_id, source_packet_id, \
          source_receipt_id, target_memory_ids, parent_memory_ids, validation_report_id, policy_ref, \
          rollback_id, route_invalidation_event_ids, evidence_refs, terminal_state, \
          production_lifecycle_approval, idempotency_key, action_body, created_at) \
         VALUES ('action-rls', 'writeback', $1, 'project-rls', 'default', 'did:example:actor', \
                 'packet-rls', 'receipt-rls', $2, $2, 'validation-rls', 'policy-rls', \
                 'rollback-rls', $2, $2, 'accepted', 'approved', 'lifecycle-idempotency-rls', \
                 $3, '2026-06-19T00:00:00Z')",
    )
    .bind(tenant_id)
    .bind(&empty_refs)
    .bind(json!({"action": "writeback"}))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_route_invalidation_events \
         (event_id, tenant_id, project_id, memory_namespace, route_id, source_action_id, \
          impacted_memory_ids, reason, invalidated_packet_ids, freshness_state_before, \
          freshness_state_after, retrieval_readiness_impact, validation_report_id, rollback_ref, \
          idempotency_key, event_body, created_at) \
         VALUES ('route-invalidation-rls', $1, 'project-rls', 'default', 'route-rls', \
                 'action-rls', $2, 'memory changed', $2, 'current', 'stale', \
                 'reject_until_rebuilt', 'validation-rls', 'rollback-rls', \
                 'route-invalidation-idempotency-rls', $3, '2026-06-19T00:00:00Z')",
    )
    .bind(tenant_id)
    .bind(&empty_refs)
    .bind(json!({"event": "route_invalidated"}))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_continuation_records \
         (continuation_id, task_id, tenant_id, project_id, memory_namespace, summary_ref, memory_refs, \
          blocker_refs, validation_refs, expiry_epoch_seconds, later_retrieval_status, \
          production_lifecycle_approval, idempotency_key, record_body, created_at) \
         VALUES ('continuation-rls', 'task-rls', $1, 'project-rls', 'default', 'summary-rls', \
                 $2, $2, $2, 1, 'pending', 'approved', 'continuation-idempotency-rls', \
                 $3, '2026-06-19T00:00:00Z')",
    )
    .bind(tenant_id)
    .bind(&empty_refs)
    .bind(json!({"continuation": "pending"}))
    .execute(&mut *tx)
    .await?;
    for (node_hash, cbor_byte) in [(0xc0_u8, 0x01_u8), (0xc1_u8, 0x02_u8)] {
        sqlx::query(
            "INSERT INTO dagdb_node_dag_nodes \
             (tenant_id, namespace, hash, cbor_payload) \
             VALUES ($1, 'default', $2, $3)",
        )
        .bind(tenant_id)
        .bind(hb(node_hash))
        .bind(vec![cbor_byte])
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO dagdb_node_dag_parents \
         (tenant_id, namespace, child_hash, parent_hash) \
         VALUES ($1, 'default', $2, $3)",
    )
    .bind(tenant_id)
    .bind(hb(0xc0))
    .bind(hb(0xc1))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_committed \
         (tenant_id, namespace, hash, height) \
         VALUES ($1, 'default', $2, 1)",
    )
    .bind(tenant_id)
    .bind(hb(0xc0))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_consensus_meta \
         (tenant_id, namespace, key, value) \
         VALUES ($1, 'default', 'height', '1')",
    )
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_consensus_votes \
         (tenant_id, namespace, round, node_hash, voter_did, signature) \
         VALUES ($1, 'default', 1, $2, 'did:exo:validator-rls', $3)",
    )
    .bind(tenant_id)
    .bind(hb(0xc0))
    .bind(sig(0x11))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_commit_certificates \
         (tenant_id, namespace, node_hash, round, cbor_data) \
         VALUES ($1, 'default', $2, 1, $3)",
    )
    .bind(tenant_id)
    .bind(hb(0xc0))
    .bind(vec![0x03_u8])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_validators \
         (tenant_id, namespace, did) \
         VALUES ($1, 'default', 'did:exo:validator-rls')",
    )
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_trust_receipts \
         (tenant_id, namespace, receipt_hash, actor_did, action_type, outcome, timestamp_ms, \
          cbor_data) \
         VALUES ($1, 'default', $2, 'did:exo:validator-rls', 'commit', 'accepted', 1, $3)",
    )
    .bind(tenant_id)
    .bind(hb(0xc2))
    .bind(vec![0x04_u8])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_economy_objects \
         (tenant_id, namespace, object_kind, object_id, content_hash, created_physical_ms, \
          created_logical, cbor_data) \
         VALUES ($1, 'default', 'credit', $2, $3, 1, 0, $4)",
    )
    .bind(tenant_id)
    .bind(hb(0xc3))
    .bind(hb(0xc4))
    .bind(vec![0x05_u8])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_economy_anchors \
         (tenant_id, namespace, anchor_hash, previous_anchor_hash, object_kind, object_id, \
          object_hash, created_physical_ms, created_logical, cbor_data) \
         VALUES ($1, 'default', $2, $3, 'credit', $4, $5, 1, 0, $6)",
    )
    .bind(tenant_id)
    .bind(hb(0xc5))
    .bind(hb(0x00))
    .bind(hb(0xc3))
    .bind(hb(0xc4))
    .bind(vec![0x06_u8])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_node_economy_meta \
         (tenant_id, namespace, key, value) \
         VALUES ($1, 'default', 'last_anchor', $2)",
    )
    .bind(tenant_id)
    .bind(hb(0xc5))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_zerodentity_records \
         (tenant_id, namespace, state_family, subject_did, record_key, secondary_key, \
          cbor_payload, payload_hash) \
         VALUES ($1, 'default', 'claim', 'did:exo:zero-rls', 'claim-rls', '', $2, $3)",
    )
    .bind(tenant_id)
    .bind(vec![0x07_u8])
    .bind(hb(0xc6))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dagdb_gateway_state_records \
         (tenant_id, namespace, state_family, record_key, cbor_payload, payload_hash, \
          json_projection, created_at_physical_ms, created_at_logical, updated_at_physical_ms, \
          updated_at_logical) \
         VALUES ($1, 'default', 'session', 'session-rls', $2, $3, $4, 1, 0, 1, 0)",
    )
    .bind(tenant_id)
    .bind(vec![0x08_u8])
    .bind(hb(0xc7))
    .bind(json!({"session": "rls"}))
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

async fn apply_live_path_schema(pool: &PgPool) {
    for migration_sql in [
        DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_EXPORT_SCHEMA_SQL,
        DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL,
        DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL,
        DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL,
        DAGDB_TENANT_RLS_SCHEMA_SQL,
        DAGDB_OPERATIONAL_EVENT_TYPES_AND_RLS_EXPANSION_SCHEMA_SQL,
    ] {
        sqlx::raw_sql(migration_sql)
            .execute(pool)
            .await
            .expect("apply DAG DB live-path migration");
    }
}

fn hb(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn sig(byte: u8) -> Vec<u8> {
    vec![byte; 64]
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Some((database_url, source_env)) = test_database_url() else {
            eprintln!(
                "skipping DAG DB tenant RLS live-path postgres test: neither {TEST_DATABASE_URL_ENV} nor {CI_DATABASE_URL_ENV} is set"
            );
            return None;
        };
        eprintln!("running DAG DB tenant RLS live-path postgres test with {source_env}");
        Some(Self::new_with_database_url(label, &database_url).await)
    }

    async fn new_with_database_url(label: &str, database_url: &str) -> Self {
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut admin = PgConnection::connect(database_url)
            .await
            .expect("connect to configured DAG DB test database URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut admin)
        .await
        .expect("drop existing RLS live-path test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create RLS live-path test schema");

        let scoped_url = database_url_with_search_path(database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&scoped_url)
            .await
            .expect("connect RLS live-path test pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB base schema");
        Self {
            pool,
            schema,
            database_url: database_url.to_owned(),
        }
    }
}

fn test_database_url() -> Option<(String, &'static str)> {
    for env_name in [TEST_DATABASE_URL_ENV, CI_DATABASE_URL_ENV] {
        match std::env::var(env_name) {
            Ok(value) if !value.trim().is_empty() => return Some((value, env_name)),
            Ok(_) | Err(_) => {}
        }
    }
    None
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
                    .expect("connect for RLS live-path cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop RLS live-path test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}

struct RlsCheckedPool {
    pool: PgPool,
    role_name: Option<String>,
}

impl RlsCheckedPool {
    async fn new(db: &TestDb, label: &str) -> Self {
        if !pool_role_bypasses_rls(&db.pool).await {
            return Self {
                pool: db.pool.clone(),
                role_name: None,
            };
        }

        let role_name = format!("dagdb_rls_{}_{}", label, process::id());
        drop_rls_role_if_exists(&db.pool, &role_name).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role_name} LOGIN PASSWORD '{RLS_TEST_ROLE_PASSWORD}'"
        )))
        .execute(&db.pool)
        .await
        .expect("create RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA {} TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant schema usage to RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant table privileges to RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT EXECUTE ON FUNCTION {}.dagdb_current_tenant_id() TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant tenant helper execution to RLS checked pool role");

        let options = PgConnectOptions::from_str(&db.database_url)
            .expect("parse RLS checked pool database URL")
            .username(&role_name)
            .password(RLS_TEST_ROLE_PASSWORD)
            .options([("search_path", format!("{},public", db.schema))]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect RLS checked pool");
        Self {
            pool,
            role_name: Some(role_name),
        }
    }

    async fn cleanup(self, admin_pool: &PgPool) {
        if let Some(role_name) = self.role_name {
            self.pool.close().await;
            drop_rls_role_if_exists(admin_pool, &role_name).await;
        }
    }
}

async fn pool_role_bypasses_rls(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        .fetch_one(pool)
        .await
        .expect("query pool role RLS bypass state")
}

async fn drop_rls_role_if_exists(pool: &PgPool, role_name: &str) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(role_name)
            .fetch_one(pool)
            .await
            .expect("query RLS checked pool role existence");
    if !exists {
        return;
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role_name}")))
        .execute(pool)
        .await
        .expect("drop RLS checked pool role privileges");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE {role_name}")))
        .execute(pool)
        .await
        .expect("drop RLS checked pool role");
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}
