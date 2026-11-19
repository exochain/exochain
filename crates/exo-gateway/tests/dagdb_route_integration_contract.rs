#![cfg(feature = "production-db")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, RwLock};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use exo_api::dagdb::{
    ConsentPurpose, CouncilDecisionStatus, DagDbCatalogLookupRequest, DagDbContextPacketRequest,
    DagDbCouncilDecisionRequest, DagDbErrorEnvelope, DagDbExportRequest,
    DagDbGraphContextPacketBuildRequest, DagDbImportRequest, DagDbIntakeRequest,
    DagDbReceiptLookupRequest, DagDbRouteLookupRequest, DagDbRouteRequest, DagDbTrustCheckRequest,
    DagDbValidateRequest, DagDbWritebackRequest, DecisionSource, RiskClass, SubjectKind,
};
use exo_core::{Hash256, crypto::KeyPair};
use exo_dag_db_core::hash::RequestHashMaterial;
use exo_dag_db_domain::{
    context_packet_persistence::{
        CONTEXT_PACKET_FINALITY_PURPOSE, ContextPacketAcceptanceEvidence, ContextPacketRequest,
        ContextPacketRouteBinding, DefaultContextQuality, PacketFreshnessStatus,
        PacketPersistenceStatus, PacketValidationStatus, accept_context_packet_record,
        build_context_packet_record, canonical_context_packet_approval_payload_hash,
        canonical_idempotency_key,
    },
    default_route::{
        DEFAULT_ROUTE_FINALITY_PURPOSE, DEFAULT_ROUTE_SCHEMA_VERSION,
        DefaultRouteAcceptanceEvidence, DefaultRouteMemoryRef, DefaultRouteRecord,
        DefaultRouteSource, DefaultRouteStatus, RouteFreshnessStatus, accept_default_route_record,
        canonical_default_route_approval_payload_hash,
    },
};
use exo_dag_db_exchange::kg_import::{
    KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
    required_trace,
};
use exo_dag_db_postgres::{
    build_graph_context_packet,
    persistent_context::build_persistent_graph_context_selection,
    postgres::{
        DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL, DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL,
        DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL, DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL,
        DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL,
    },
};
use exo_gatekeeper::{
    ConsentEngine, DagDbConsentRecord, IdentityRegistry,
    dagdb_gate::{context_packet_record_payload_hash, default_route_payload_hash},
    sign_write_payload,
    types::{BailmentState, GovernedRoleName},
    usage_event_payload_hash, verify_write_signature,
};
use exo_gateway::{
    dagdb::{
        DagDbRouteContext, dagdb_router, selection_request_from_writeback,
        set_route_context_for_integration_tests, writeback_continuation_approval_payload_hash,
        writeback_lifecycle_approval_payload_hash,
    },
    server::{AppState, build_router},
};
use exo_identity::registry::LocalDidRegistry;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tower::ServiceExt;

const TENANT_ID: &str = "tenant-a";
const NAMESPACE: &str = "primary";
const AGENT_DID: &str = "did:exo:agent";
const EXPORTER_DID: &str = "did:exo:exporter";
const FINALITY_AUTHORITY_DID: &str = "did:exo:finality-authority";
const BEARER: &str = "test-token";
const FORGED_BEARER: &str = "forged-test-token";
const DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL: &str = include_str!(
    "../../exo-dag-db-postgres/migrations/20260620000001_add_dagdb_operational_receipt_event_types.sql"
);

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str, database_url: &str) -> Self {
        let schema = format!("dagdb_route_m14_{label}_{}", std::process::id());
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
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

        let scoped_url = database_url_with_search_path(database_url, &schema);
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
        sqlx::raw_sql(DAGDB_EXPORT_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB export schema");
        sqlx::raw_sql(DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB export finality/outbox schema");
        sqlx::raw_sql(DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB operational receipt event-type schema");
        sqlx::raw_sql(DAGDB_TELEMETRY_FACET_NODE_TYPE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB telemetry-facet node_type schema");
        sqlx::raw_sql(DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB PRD17 default-route schema");
        sqlx::raw_sql(DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB PRD17 context-packet schema");
        sqlx::raw_sql(DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB PRD17 lifecycle schema");
        assert_export_schema_tables_present(&pool).await;
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
            "#,
        )
        .execute(&pool)
        .await
        .expect("apply gateway auth tables");
        Self {
            admin_pool,
            pool,
            schema,
        }
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
async fn dagdb_routes_integration_contract() {
    default_route_approval_signature_binds_request_and_purpose();

    let Some(database_url) = configured_database_url("dagdb_routes_integration_contract") else {
        return;
    };
    let db = TestDb::new("integration", &database_url).await;

    let keypair = KeyPair::generate();
    let ctx = Arc::new(DagDbRouteContext::from_pool(Some(db.pool.clone())));
    set_route_context_for_integration_tests(ctx.clone());
    insert_session_user(&db.pool, BEARER, AGENT_DID, TENANT_ID).await;

    let app = build_router(AppState::new(
        Some(db.pool.clone()),
        Arc::new(RwLock::new(LocalDidRegistry::new())),
    ));

    let import_request = DagDbImportRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-import-integration".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        source_hash: h(0x01),
        requester_did: AGENT_DID.to_owned(),
        import_report: base_report(),
    };
    let forged_bearer_response = app
        .clone()
        .oneshot(scoped_post_with_bearer(
            FORGED_BEARER,
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            None,
        ))
        .await
        .expect("forged bearer response");
    assert_eq!(forged_bearer_response.status(), StatusCode::UNAUTHORIZED);
    let receipts_before_missing_import_signature =
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_import_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let idempotency_before_missing_import_signature =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let memory_objects_before_missing_import_signature =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let missing_import_signature = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            None,
        ))
        .await
        .expect("missing import signature response");
    assert_eq!(missing_import_signature.status(), StatusCode::BAD_REQUEST);
    let missing_import_signature_body: DagDbErrorEnvelope =
        response_json(missing_import_signature).await;
    assert_eq!(
        missing_import_signature_body.error_code,
        "write_signature_required"
    );
    assert_eq!(
        missing_import_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_missing_import_signature + 1,
        "missing import signature must append one durable operational receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_import_signature + 1,
        "missing import signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_missing_import_signature,
        "missing import signature must fail before idempotency reservation"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_import_signature,
        "missing import signature must not mutate import data"
    );

    let mut scope_mismatch_import = import_request.clone();
    scope_mismatch_import.idempotency_key = "idem-import-scope-mismatch".to_owned();
    scope_mismatch_import.import_report["tenant_id"] = json!("tenant-b");
    let scope_mismatch_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &scope_mismatch_import,
            None,
        ))
        .await
        .expect("import scope mismatch response");
    assert_eq!(scope_mismatch_response.status(), StatusCode::BAD_REQUEST);
    let scope_mismatch_body: DagDbErrorEnvelope = response_json(scope_mismatch_response).await;
    assert_eq!(scope_mismatch_body.error_code, "invalid_request_shape");
    assert_no_forbidden_material(&scope_mismatch_body.message);

    let mut namespace_scope_mismatch_import = import_request.clone();
    namespace_scope_mismatch_import.idempotency_key = "idem-import-namespace-mismatch".to_owned();
    namespace_scope_mismatch_import.import_report["namespace"] = json!("secondary");
    let namespace_scope_mismatch_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &namespace_scope_mismatch_import,
            None,
        ))
        .await
        .expect("import namespace scope mismatch response");
    assert_eq!(
        namespace_scope_mismatch_response.status(),
        StatusCode::BAD_REQUEST
    );
    let namespace_scope_mismatch_body: DagDbErrorEnvelope =
        response_json(namespace_scope_mismatch_response).await;
    assert_eq!(
        namespace_scope_mismatch_body.error_code,
        "invalid_request_shape"
    );
    assert_no_forbidden_material(&namespace_scope_mismatch_body.message);

    let mut empty_field_import = import_request.clone();
    empty_field_import.idempotency_key = " ".to_owned();
    let empty_field_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &empty_field_import,
            None,
        ))
        .await
        .expect("empty import runtime field response");
    assert_eq!(empty_field_response.status(), StatusCode::BAD_REQUEST);
    let empty_field_body: DagDbErrorEnvelope = response_json(empty_field_response).await;
    assert_eq!(empty_field_body.error_code, "invalid_request_shape");
    assert_no_forbidden_material(&empty_field_body.message);

    let invalid_requester_export = DagDbExportRequest {
        idempotency_key: "idem-export-invalid-requester".to_owned(),
        requester_did: "not-a-did".to_owned(),
        ..export_request()
    };
    let invalid_requester_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &invalid_requester_export,
            None,
        ))
        .await
        .expect("invalid export requester response");
    assert_eq!(invalid_requester_response.status(), StatusCode::BAD_REQUEST);
    let invalid_requester_body: DagDbErrorEnvelope =
        response_json(invalid_requester_response).await;
    assert_eq!(invalid_requester_body.error_code, "invalid_request_shape");
    assert_no_forbidden_material(&invalid_requester_body.message);

    ctx.install_gatekeeper_profile(
        ConsentEngine::default(),
        identity_registry_with_finality_authority(&keypair),
    );
    let approval_denied_before_denied_import =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let idempotency_before_denied_import =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let denied_import_request = DagDbImportRequest {
        idempotency_key: "idem-import-denied-no-consent".to_owned(),
        ..import_request.clone()
    };
    let denied_import_signatures =
        import_signatures(&db.pool, &keypair, &denied_import_request).await;
    let denied_import = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &denied_import_request,
            Some(denied_import_signatures.write_signature),
            Some(denied_import_signatures.finality_signature),
        ))
        .await
        .expect("consent denied import response");
    assert_eq!(denied_import.status(), StatusCode::FORBIDDEN);
    let denied_import_body: DagDbErrorEnvelope = response_json(denied_import).await;
    assert_eq!(denied_import_body.error_code, "consent_denied");
    assert_eq!(
        denied_import_body.operational_event_type.as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_no_forbidden_material(&denied_import_body.message);
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denied_before_denied_import + 1,
        "import consent denial must persist dagdb_approval_denied"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_denied_import,
        "import consent denial must clean its idempotency reservation"
    );

    ctx.install_gatekeeper_profile(
        active_consent_engine(),
        identity_registry_with_finality_authority(&keypair),
    );
    let receipts_before_import_consent_gap = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let approval_denied_before_import_consent_gap =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let idempotency_before_import_consent_gap =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let initial_import_signatures = import_signatures(&db.pool, &keypair, &import_request).await;
    let import_response = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            Some(initial_import_signatures.write_signature.clone()),
            Some(initial_import_signatures.finality_signature.clone()),
        ))
        .await
        .expect("import response");
    assert_eq!(import_response.status(), StatusCode::FORBIDDEN);
    let import_body: DagDbErrorEnvelope = response_json(import_response).await;
    assert_eq!(import_body.error_code, "consent_denied");
    assert_eq!(
        import_body.operational_event_type.as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_no_forbidden_material(&import_body.message);
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_import_consent_gap + 1,
        "writeback consent must only append an operational denial receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denied_before_import_consent_gap + 1,
        "writeback consent gap must persist dagdb_approval_denied for import"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_import_consent_gap,
        "writeback consent must not leave an import idempotency reservation"
    );

    ctx.install_gatekeeper_profile(
        active_import_export_consent_engine(),
        identity_registry_with_finality_authority(&keypair),
    );
    let rls_violations_before_tenant_mismatch_import =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_rls_tenant_violation").await;
    let idempotency_before_tenant_mismatch_import =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let tenant_mismatch_import = DagDbImportRequest {
        tenant_id: "tenant-b".to_owned(),
        idempotency_key: "idem-import-tenant-mismatch".to_owned(),
        ..import_request.clone()
    };
    let tenant_mismatch_import_response = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &tenant_mismatch_import,
            Some(initial_import_signatures.write_signature.clone()),
            Some(initial_import_signatures.finality_signature.clone()),
        ))
        .await
        .expect("import tenant mismatch response");
    assert_eq!(
        tenant_mismatch_import_response.status(),
        StatusCode::FORBIDDEN
    );
    let tenant_mismatch_import_body: DagDbErrorEnvelope =
        response_json(tenant_mismatch_import_response).await;
    assert_eq!(
        tenant_mismatch_import_body.error_code,
        "tenant_scope_mismatch"
    );
    assert_eq!(
        tenant_mismatch_import_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_rls_tenant_violation")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_rls_tenant_violation").await,
        rls_violations_before_tenant_mismatch_import + 1,
        "import tenant mismatch must persist dagdb_rls_tenant_violation under the mounted scope"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_tenant_mismatch_import,
        "import tenant mismatch must not leave an idempotency reservation"
    );
    let signature_failures_before_forged_import =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let idempotency_before_forged_import =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let forged_import_material = DagDbImportRequest {
        idempotency_key: "idem-import-forged-signature".to_owned(),
        source_hash: h(0x03),
        ..import_request.clone()
    };
    let forged_import_response = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &forged_import_material,
            Some(initial_import_signatures.write_signature.clone()),
            Some(initial_import_signatures.finality_signature.clone()),
        ))
        .await
        .expect("forged import signature response");
    assert_eq!(forged_import_response.status(), StatusCode::FORBIDDEN);
    let forged_import_body: DagDbErrorEnvelope = response_json(forged_import_response).await;
    assert_eq!(forged_import_body.error_code, "provenance_denied");
    assert_eq!(
        forged_import_body.operational_event_type.as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_forged_import + 1,
        "forged import signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_forged_import,
        "forged import signature must clean its idempotency reservation"
    );
    let receipts_before_import_success = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let import_completed_before_success =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_import_completed").await;
    let approval_counts_before_import_success =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let idempotency_before_import_success =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await;
    let import_success_signatures = import_signatures(&db.pool, &keypair, &import_request).await;
    let import_success = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            Some(import_success_signatures.write_signature.clone()),
            Some(import_success_signatures.finality_signature.clone()),
        ))
        .await
        .expect("import success response");
    assert_eq!(import_success.status(), StatusCode::OK);
    let import_success_body: JsonValue = response_json(import_success).await;
    assert_eq!(import_success_body["import_status"], "persisted");
    assert_eq!(import_success_body["idempotency_status"], "stored");
    assert!(
        import_success_body["imported_record_count"]
            .as_u64()
            .unwrap_or_default()
            > 0,
        "import must persist real DAG DB report rows"
    );
    assert!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await > receipts_before_import_success,
        "import must append persisted DAG DB receipts"
    );
    assert!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_import_completed").await
            > import_completed_before_success,
        "import success must append a durable dagdb_import_completed receipt"
    );
    assert_approval_counts_increased(
        approval_counts_before_import_success,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "import success",
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.import").await,
        idempotency_before_import_success + 1,
        "import success must store one idempotency response"
    );
    let receipts_before_import_replay = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let replay_detected_before_import_replay =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_replay_detected").await;
    let import_completed_before_import_replay =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_import_completed").await;
    let approval_counts_before_import_replay =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let import_replay = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            Some(import_success_signatures.write_signature),
            Some(import_success_signatures.finality_signature),
        ))
        .await
        .expect("import replay response");
    assert_eq!(import_replay.status(), StatusCode::OK);
    let import_replay_body: JsonValue = response_json(import_replay).await;
    let mut expected_import_replay_body = import_success_body.clone();
    expected_import_replay_body["idempotency_status"] = JsonValue::String("replayed".to_owned());
    assert_eq!(import_replay_body, expected_import_replay_body);
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_import_replay + 1,
        "idempotent import replay must append exactly one operational receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_replay_detected").await,
        replay_detected_before_import_replay + 1,
        "idempotent import replay must persist dagdb_replay_detected"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_import_completed").await,
        import_completed_before_import_replay,
        "idempotent import replay must not append duplicate dagdb_import_completed receipts"
    );
    assert_approval_counts_unchanged(
        approval_counts_before_import_replay,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "idempotent import replay",
    );
    let changed_import_material = DagDbImportRequest {
        source_hash: h(0x02),
        ..import_request.clone()
    };
    let idempotency_conflicts_before_changed_import =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_idempotency_conflict").await;
    let changed_import_signatures =
        import_signatures(&db.pool, &keypair, &changed_import_material).await;
    let changed_import_response = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &changed_import_material,
            Some(changed_import_signatures.write_signature),
            Some(changed_import_signatures.finality_signature),
        ))
        .await
        .expect("changed import idempotency response");
    assert_eq!(changed_import_response.status(), StatusCode::CONFLICT);
    let changed_import_body: DagDbErrorEnvelope = response_json(changed_import_response).await;
    assert_eq!(changed_import_body.error_code, "idempotency_key_conflict");
    assert_eq!(
        changed_import_body.operational_event_type.as_deref(),
        Some("dagdb_idempotency_conflict")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_idempotency_conflict").await,
        idempotency_conflicts_before_changed_import + 1,
        "changed import material must persist dagdb_idempotency_conflict"
    );

    let default_route_request = DagDbRouteRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-route-d5-accepted".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        task_signature_hash: h(0x52),
        approved_scope_hash: h(0x53),
        token_budget: 2048,
        start_catalog_id: None,
        requested_memory_ids: Some(vec![h(0x10)]),
        credential_id: None,
    };
    let default_route_sigs = default_route_signatures(&keypair, &default_route_request);
    let route_rows_before_missing_signature = default_route_count(&db.pool).await;
    let receipts_before_missing_route_signature =
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_route_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_route_signature_request = DagDbRouteRequest {
        idempotency_key: "idem-route-missing-write-signature".to_owned(),
        ..default_route_request.clone()
    };
    let missing_route_signature = app
        .clone()
        .oneshot(scoped_post_with_default_route_signature(
            "/api/v1/dag-db/route",
            "dagdb:route",
            &missing_route_signature_request,
            None,
            Some(default_route_sigs.approval_signature.clone()),
        ))
        .await
        .expect("missing route write signature response");
    assert_eq!(missing_route_signature.status(), StatusCode::BAD_REQUEST);
    let missing_route_signature_body: DagDbErrorEnvelope =
        response_json(missing_route_signature).await;
    assert_eq!(
        missing_route_signature_body.error_code,
        "write_signature_required"
    );
    assert_eq!(
        missing_route_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_missing_route_signature + 1,
        "missing route write signature must append one durable operational receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_route_signature + 1,
        "missing route write signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        default_route_count(&db.pool).await,
        route_rows_before_missing_signature,
        "missing route write signature must not persist a default route"
    );

    let route_rows_before_missing_approval = default_route_count(&db.pool).await;
    let signature_failures_before_missing_route_approval =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_route_approval_request = DagDbRouteRequest {
        idempotency_key: "idem-route-missing-approval-signature".to_owned(),
        ..default_route_request.clone()
    };
    let missing_route_approval = app
        .clone()
        .oneshot(scoped_post_with_default_route_signature(
            "/api/v1/dag-db/route",
            "dagdb:route",
            &missing_route_approval_request,
            Some(default_route_sigs.write_signature.clone()),
            None,
        ))
        .await
        .expect("missing route approval signature response");
    assert_eq!(missing_route_approval.status(), StatusCode::BAD_REQUEST);
    let missing_route_approval_body: DagDbErrorEnvelope =
        response_json(missing_route_approval).await;
    assert_eq!(
        missing_route_approval_body.error_code,
        "default_route_approval_signature_required"
    );
    assert_eq!(
        missing_route_approval_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_route_approval + 1,
        "missing route approval signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        default_route_count(&db.pool).await,
        route_rows_before_missing_approval,
        "missing route approval signature must not persist a default route"
    );

    let route_rows_before_missing_approval_did = default_route_count(&db.pool).await;
    let approval_denials_before_missing_route_did =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let missing_route_approval_did_request = DagDbRouteRequest {
        idempotency_key: "idem-route-missing-approval-did".to_owned(),
        ..default_route_request.clone()
    };
    let mut missing_route_approval_did_request_http = scoped_post_with_default_route_signature(
        "/api/v1/dag-db/route",
        "dagdb:route",
        &missing_route_approval_did_request,
        Some(default_route_sigs.write_signature.clone()),
        Some(default_route_sigs.approval_signature.clone()),
    );
    missing_route_approval_did_request_http
        .headers_mut()
        .remove("x-exo-default-route-approval-did");
    let missing_route_approval_did = app
        .clone()
        .oneshot(missing_route_approval_did_request_http)
        .await
        .expect("missing route approval DID response");
    assert_eq!(missing_route_approval_did.status(), StatusCode::BAD_REQUEST);
    let missing_route_approval_did_body: DagDbErrorEnvelope =
        response_json(missing_route_approval_did).await;
    assert_eq!(
        missing_route_approval_did_body.error_code,
        "default_route_approval_authority_required"
    );
    assert_eq!(
        missing_route_approval_did_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denials_before_missing_route_did + 1,
        "missing route approval DID must persist dagdb_approval_denied"
    );
    assert_eq!(
        default_route_count(&db.pool).await,
        route_rows_before_missing_approval_did,
        "missing route approval DID must not persist a default route"
    );

    let record_accepted_before_default_route =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await;
    let approval_counts_before_default_route =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let default_route_response = app
        .clone()
        .oneshot(scoped_post_with_default_route_signature(
            "/api/v1/dag-db/route",
            "dagdb:route",
            &default_route_request,
            Some(default_route_sigs.write_signature),
            Some(default_route_sigs.approval_signature),
        ))
        .await
        .expect("default route response");
    let default_route_status = default_route_response.status();
    let default_route_body: JsonValue = response_json(default_route_response).await;
    assert_eq!(
        default_route_status,
        StatusCode::CREATED,
        "default route response body: {default_route_body}"
    );
    let default_route_id = default_route_body["route_id"]
        .as_str()
        .expect("route_id")
        .to_owned();
    let default_route_state = default_route_d5_state(&db.pool, &default_route_id).await;
    assert_eq!(
        default_route_state.production_default_route_approval_status,
        "accepted"
    );
    assert_eq!(default_route_state.packet_quality_review_status, "accepted");
    assert!(
        default_route_state.selected_memory_ref_count > 0,
        "default route must persist selected memory evidence"
    );
    assert!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await
            > record_accepted_before_default_route,
        "default route success must append a durable dagdb_record_accepted receipt"
    );
    assert_approval_counts_increased(
        approval_counts_before_default_route,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "default route success",
    );

    let default_route_rows_before_missing = default_route_count(&db.pool).await;
    let missing_memory_route = DagDbRouteRequest {
        idempotency_key: "idem-route-missing-memory".to_owned(),
        requested_memory_ids: None,
        ..default_route_request.clone()
    };
    let missing_memory_route_response = app
        .clone()
        .oneshot(scoped_post_with_default_route_signature(
            "/api/v1/dag-db/route",
            "dagdb:route",
            &missing_memory_route,
            Some("00".repeat(64)),
            Some("00".repeat(64)),
        ))
        .await
        .expect("missing memory route response");
    assert_eq!(
        missing_memory_route_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let missing_memory_route_body: DagDbErrorEnvelope =
        response_json(missing_memory_route_response).await;
    assert_eq!(missing_memory_route_body.error_code, "metadata_rejected");
    assert_eq!(
        default_route_count(&db.pool).await,
        default_route_rows_before_missing,
        "missing memory evidence must not persist a default route"
    );

    let packet_request_denied = DagDbContextPacketRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-packet-2".to_owned(),
        request_id: "request-2".to_owned(),
        route_id: h(0x40),
        task_hash: h(0x51),
        requesting_agent_did: AGENT_DID.to_owned(),
        token_budget: 2048,
        force_revalidate: None,
        max_memory_refs: None,
        task: None,
        layered_mode: None,
        max_layer_depth: None,
        require_layer_evidence: None,
        drilldown_reserve_bp: None,
    };
    let unauthenticated = app
        .clone()
        .oneshot(unauthenticated_post(
            "/api/v1/dag-db/context-packet",
            &packet_request_denied,
        ))
        .await
        .expect("unauthenticated response");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let unauth_body: DagDbErrorEnvelope = response_json(unauthenticated).await;
    assert_eq!(unauth_body.error_code, "unauthenticated");

    // A forged bearer with self-asserted tenant/namespace/scope headers must
    // not reach persisted tenant data on the signature-free read path: the
    // token must resolve to a live DB-backed session for the tenant.
    let forged_bearer_packet = app
        .clone()
        .oneshot(scoped_post_with_bearer(
            FORGED_BEARER,
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            &packet_request_denied,
            None,
        ))
        .await
        .expect("forged bearer context packet response");
    assert_eq!(forged_bearer_packet.status(), StatusCode::UNAUTHORIZED);
    let forged_packet_body: DagDbErrorEnvelope = response_json(forged_bearer_packet).await;
    assert_eq!(forged_packet_body.error_code, "unauthenticated");

    ctx.install_gatekeeper_profile(
        ConsentEngine::default(),
        identity_registry_with_finality_authority(&keypair),
    );
    let writeback_request_denied = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-2".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x81),
        route_id: h(0x91),
        context_packet_id: h(0xa0),
        validation_report_id: h(0xb1),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let selection_denied = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&writeback_request_denied)
            .expect("selection request for denied writeback"),
    )
    .await
    .expect("selection for signature");
    let signature_denied = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&selection_denied.selection).expect("hash"),
    )
    .expect("signature");
    let (lifecycle_signature_denied, continuation_signature_denied) =
        writeback_d5_signatures(&keypair, &writeback_request_denied);
    let denied = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request_denied,
            Some(signature_denied),
            Some(lifecycle_signature_denied),
            Some(continuation_signature_denied),
        ))
        .await
        .expect("consent denied response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied_body: DagDbErrorEnvelope = response_json(denied).await;
    assert_eq!(denied_body.error_code, "consent_denied");

    let writeback_request_missing_signature = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-missing-signature".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x82),
        route_id: h(0x92),
        context_packet_id: h(0xa1),
        validation_report_id: h(0xb2),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let receipts_before_missing_writeback_signature =
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_writeback_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let memory_objects_before_missing_writeback_signature =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let missing_signature = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request_missing_signature,
            None,
        ))
        .await
        .expect("missing write signature response");
    assert_eq!(missing_signature.status(), StatusCode::BAD_REQUEST);
    let missing_signature_body: DagDbErrorEnvelope = response_json(missing_signature).await;
    assert_eq!(
        missing_signature_body.error_code,
        "write_signature_required"
    );
    assert_eq!(
        missing_signature_body.operational_event_type.as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_missing_writeback_signature + 1,
        "missing writeback write signature must append one durable operational receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_writeback_signature + 1,
        "missing writeback write signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_writeback_signature,
        "missing writeback write signature must not persist user data"
    );

    ctx.install_gatekeeper_profile(
        active_consent_engine(),
        identity_registry_with_finality_authority(&keypair),
    );

    let packet_request = DagDbContextPacketRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-packet-1".to_owned(),
        request_id: "request-1".to_owned(),
        route_id: default_route_id.clone(),
        task_hash: h(0x50),
        requesting_agent_did: AGENT_DID.to_owned(),
        token_budget: 2048,
        force_revalidate: Some(false),
        max_memory_refs: Some(8),
        task: Some("Implement live gateway context packet selection for DAG DB MCP".to_owned()),
        layered_mode: None,
        max_layer_depth: None,
        require_layer_evidence: None,
        drilldown_reserve_bp: None,
    };
    let packet_signatures = context_packet_signatures(&db.pool, &keypair, &packet_request).await;
    let packet_rows_before_missing_signature = context_packet_count(&db.pool).await;
    let signature_failures_before_missing_packet_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_packet_signature_request = DagDbContextPacketRequest {
        idempotency_key: "idem-packet-missing-write-signature".to_owned(),
        request_id: "request-missing-write-signature".to_owned(),
        ..packet_request.clone()
    };
    let missing_packet_signature = app
        .clone()
        .oneshot(scoped_post_with_context_packet_signature(
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            &missing_packet_signature_request,
            None,
            Some(packet_signatures.approval_signature.clone()),
        ))
        .await
        .expect("missing context packet write signature response");
    assert_eq!(missing_packet_signature.status(), StatusCode::BAD_REQUEST);
    let missing_packet_signature_body: DagDbErrorEnvelope =
        response_json(missing_packet_signature).await;
    assert_eq!(
        missing_packet_signature_body.error_code,
        "write_signature_required"
    );
    assert_eq!(
        missing_packet_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_packet_signature + 1,
        "missing context packet write signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        context_packet_count(&db.pool).await,
        packet_rows_before_missing_signature,
        "missing context packet write signature must not persist packet state"
    );

    let packet_rows_before_missing_approval = context_packet_count(&db.pool).await;
    let signature_failures_before_missing_packet_approval =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_packet_approval_request = DagDbContextPacketRequest {
        idempotency_key: "idem-packet-missing-approval-signature".to_owned(),
        request_id: "request-missing-approval-signature".to_owned(),
        ..packet_request.clone()
    };
    let missing_packet_approval = app
        .clone()
        .oneshot(scoped_post_with_context_packet_signature(
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            &missing_packet_approval_request,
            Some(packet_signatures.write_signature.clone()),
            None,
        ))
        .await
        .expect("missing context packet approval signature response");
    assert_eq!(missing_packet_approval.status(), StatusCode::BAD_REQUEST);
    let missing_packet_approval_body: DagDbErrorEnvelope =
        response_json(missing_packet_approval).await;
    assert_eq!(
        missing_packet_approval_body.error_code,
        "context_packet_approval_signature_required"
    );
    assert_eq!(
        missing_packet_approval_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_packet_approval + 1,
        "missing context packet approval signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        context_packet_count(&db.pool).await,
        packet_rows_before_missing_approval,
        "missing context packet approval signature must not persist packet state"
    );

    let packet_rows_before_missing_approval_did = context_packet_count(&db.pool).await;
    let approval_denials_before_missing_packet_did =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let missing_packet_approval_did_request = DagDbContextPacketRequest {
        idempotency_key: "idem-packet-missing-approval-did".to_owned(),
        request_id: "request-missing-approval-did".to_owned(),
        ..packet_request.clone()
    };
    let mut missing_packet_approval_did_request_http = scoped_post_with_context_packet_signature(
        "/api/v1/dag-db/context-packet",
        "dagdb:context_packet",
        &missing_packet_approval_did_request,
        Some(packet_signatures.write_signature.clone()),
        Some(packet_signatures.approval_signature.clone()),
    );
    missing_packet_approval_did_request_http
        .headers_mut()
        .remove("x-exo-context-packet-approval-did");
    let missing_packet_approval_did = app
        .clone()
        .oneshot(missing_packet_approval_did_request_http)
        .await
        .expect("missing context packet approval DID response");
    assert_eq!(
        missing_packet_approval_did.status(),
        StatusCode::BAD_REQUEST
    );
    let missing_packet_approval_did_body: DagDbErrorEnvelope =
        response_json(missing_packet_approval_did).await;
    assert_eq!(
        missing_packet_approval_did_body.error_code,
        "context_packet_approval_authority_required"
    );
    assert_eq!(
        missing_packet_approval_did_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denials_before_missing_packet_did + 1,
        "missing context packet approval DID must persist dagdb_approval_denied"
    );
    assert_eq!(
        context_packet_count(&db.pool).await,
        packet_rows_before_missing_approval_did,
        "missing context packet approval DID must not persist packet state"
    );

    let record_accepted_before_packet =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await;
    let approval_counts_before_packet = approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let packet_response = app
        .clone()
        .oneshot(scoped_post_with_context_packet_signature(
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            &packet_request,
            Some(packet_signatures.write_signature),
            Some(packet_signatures.approval_signature),
        ))
        .await
        .expect("context packet response");
    assert_eq!(packet_response.status(), StatusCode::OK);
    let packet_body: JsonValue = response_json(packet_response).await;
    assert_eq!(packet_body["tenant_id"], TENANT_ID);
    assert!(!packet_body["memory_refs"].as_array().unwrap().is_empty());
    if packet_body["validation_status"] == "passed" {
        for memory_ref in packet_body["memory_refs"].as_array().unwrap() {
            assert_ne!(
                memory_ref["latest_receipt_hash"],
                JsonValue::String(exo_core::Hash256::ZERO.to_string())
            );
        }
    } else {
        assert_eq!(packet_body["validation_status"], "failed");
        assert!(
            packet_body["selection_warning"]
                .as_str()
                .unwrap_or_default()
                .contains("receipt hash unavailable")
        );
    }
    assert_no_forbidden_material(&packet_body.to_string());

    let context_packet_id = packet_body["context_packet_id"]
        .as_str()
        .expect("context_packet_id")
        .to_owned();
    let packet_state = context_packet_d5_state(&db.pool, &context_packet_id).await;
    assert_eq!(
        packet_state.production_default_route_approval_status,
        "accepted"
    );
    assert_eq!(packet_state.packet_quality_review_status, "accepted");
    assert_eq!(packet_state.context_quality, "usable_context");
    assert_eq!(packet_state.validation_status, "passed");
    assert!(
        packet_state.selected_memory_count > 0,
        "context packet must persist selected memory evidence"
    );
    assert!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await
            > record_accepted_before_packet,
        "context packet success must append a durable dagdb_record_accepted receipt"
    );
    assert_approval_counts_increased(
        approval_counts_before_packet,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "context packet success",
    );

    let empty_selection_packet = DagDbContextPacketRequest {
        idempotency_key: "idem-packet-empty-selection".to_owned(),
        request_id: "request-empty-selection".to_owned(),
        task_hash: h(0x54),
        token_budget: 1,
        ..packet_request.clone()
    };
    let packet_rows_before_empty = context_packet_count(&db.pool).await;
    let empty_selection_response = app
        .clone()
        .oneshot(scoped_post_with_context_packet_signature(
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            &empty_selection_packet,
            Some("00".repeat(64)),
            Some("00".repeat(64)),
        ))
        .await
        .expect("empty selection context packet response");
    assert_eq!(
        empty_selection_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let empty_selection_body: DagDbErrorEnvelope = response_json(empty_selection_response).await;
    assert_eq!(empty_selection_body.error_code, "metadata_rejected");
    assert_eq!(
        context_packet_count(&db.pool).await,
        packet_rows_before_empty,
        "missing selected memory evidence must not persist a context packet"
    );

    let receipts_before = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let writeback_request = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-1".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x80),
        route_id: h(0x90),
        context_packet_id,
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
    };
    // Sign over the same selection material the gateway reconstructs from the
    // writeback request (selection_request_from_writeback binds summary_text /
    // knowledge_class into the signed task hash), so the operator signature
    // cryptographically covers the persisted searchable metadata.
    let selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&writeback_request)
            .expect("selection request for writeback"),
    )
    .await
    .expect("selection for signature");
    let payload_hash = usage_event_payload_hash(&selection.selection).expect("payload hash");
    let signature = sign_write_payload(&keypair, &payload_hash).expect("signature");
    let (lifecycle_signature, continuation_signature) =
        writeback_d5_signatures(&keypair, &writeback_request);

    let memory_objects_before_missing_lifecycle_signature =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_lifecycle_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_lifecycle_signature_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-missing-lifecycle-signature".to_owned(),
        ..writeback_request.clone()
    };
    let missing_lifecycle_signature = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &missing_lifecycle_signature_request,
            Some(signature.clone()),
            None,
            Some(continuation_signature.clone()),
        ))
        .await
        .expect("missing lifecycle signature response");
    assert_eq!(
        missing_lifecycle_signature.status(),
        StatusCode::BAD_REQUEST
    );
    let missing_lifecycle_signature_body: DagDbErrorEnvelope =
        response_json(missing_lifecycle_signature).await;
    assert_eq!(
        missing_lifecycle_signature_body.error_code,
        "lifecycle_signature_required"
    );
    assert_eq!(
        missing_lifecycle_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_lifecycle_signature + 1,
        "missing lifecycle signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_lifecycle_signature,
        "missing lifecycle signature must not persist user data"
    );

    let memory_objects_before_missing_continuation_signature =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_continuation_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let missing_continuation_signature_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-missing-continuation-signature".to_owned(),
        ..writeback_request.clone()
    };
    let missing_continuation_signature = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &missing_continuation_signature_request,
            Some(signature.clone()),
            Some(lifecycle_signature.clone()),
            None,
        ))
        .await
        .expect("missing continuation signature response");
    assert_eq!(
        missing_continuation_signature.status(),
        StatusCode::BAD_REQUEST
    );
    let missing_continuation_signature_body: DagDbErrorEnvelope =
        response_json(missing_continuation_signature).await;
    assert_eq!(
        missing_continuation_signature_body.error_code,
        "continuation_signature_required"
    );
    assert_eq!(
        missing_continuation_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_continuation_signature + 1,
        "missing continuation signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_continuation_signature,
        "missing continuation signature must not persist user data"
    );

    let memory_objects_before_missing_lifecycle_did =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let approval_denials_before_missing_lifecycle_did =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let missing_lifecycle_did_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-missing-lifecycle-did".to_owned(),
        ..writeback_request.clone()
    };
    let mut missing_lifecycle_did_request_http = scoped_post_with_d5_signatures(
        "/api/v1/dag-db/writeback",
        "dagdb:writeback",
        &missing_lifecycle_did_request,
        Some(signature.clone()),
        Some(lifecycle_signature.clone()),
        Some(continuation_signature.clone()),
    );
    missing_lifecycle_did_request_http
        .headers_mut()
        .remove("x-exo-lifecycle-approval-did");
    let missing_lifecycle_did = app
        .clone()
        .oneshot(missing_lifecycle_did_request_http)
        .await
        .expect("missing lifecycle approval DID response");
    assert_eq!(missing_lifecycle_did.status(), StatusCode::BAD_REQUEST);
    let missing_lifecycle_did_body: DagDbErrorEnvelope = response_json(missing_lifecycle_did).await;
    assert_eq!(
        missing_lifecycle_did_body.error_code,
        "lifecycle_approval_authority_required"
    );
    assert_eq!(
        missing_lifecycle_did_body.operational_event_type.as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denials_before_missing_lifecycle_did + 1,
        "missing lifecycle approval DID must persist dagdb_approval_denied"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_lifecycle_did,
        "missing lifecycle approval DID must not persist user data"
    );

    let memory_objects_before_missing_continuation_did =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let approval_denials_before_missing_continuation_did =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let missing_continuation_did_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-missing-continuation-did".to_owned(),
        ..writeback_request.clone()
    };
    let mut missing_continuation_did_request_http = scoped_post_with_d5_signatures(
        "/api/v1/dag-db/writeback",
        "dagdb:writeback",
        &missing_continuation_did_request,
        Some(signature.clone()),
        Some(lifecycle_signature.clone()),
        Some(continuation_signature.clone()),
    );
    missing_continuation_did_request_http
        .headers_mut()
        .remove("x-exo-continuation-approval-did");
    let missing_continuation_did = app
        .clone()
        .oneshot(missing_continuation_did_request_http)
        .await
        .expect("missing continuation approval DID response");
    assert_eq!(missing_continuation_did.status(), StatusCode::BAD_REQUEST);
    let missing_continuation_did_body: DagDbErrorEnvelope =
        response_json(missing_continuation_did).await;
    assert_eq!(
        missing_continuation_did_body.error_code,
        "continuation_approval_authority_required"
    );
    assert_eq!(
        missing_continuation_did_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denials_before_missing_continuation_did + 1,
        "missing continuation approval DID must persist dagdb_approval_denied"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_missing_continuation_did,
        "missing continuation approval DID must not persist user data"
    );

    let receipts_before_metadata_relay = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let memory_objects_before_metadata_relay =
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let mutated_summary_relay_request = DagDbWritebackRequest {
        summary_text: Some("Attacker-mutated searchable summary".to_owned()),
        ..writeback_request.clone()
    };
    let mutated_summary_relay = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &mutated_summary_relay_request,
            Some(signature.clone()),
            Some(lifecycle_signature.clone()),
            Some(continuation_signature.clone()),
        ))
        .await
        .expect("mutated summary relay response");
    assert_eq!(
        mutated_summary_relay.status(),
        StatusCode::FORBIDDEN,
        "a writeback signature must not authorize a mutated summary_text"
    );
    let mutated_summary_relay_body: DagDbErrorEnvelope = response_json(mutated_summary_relay).await;
    assert_eq!(mutated_summary_relay_body.error_code, "provenance_denied");
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_metadata_relay,
        "mutated summary relay must not persist DAG DB receipts"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_metadata_relay,
        "mutated summary relay must not persist DAG DB memory rows"
    );

    let mutated_knowledge_class_relay_request = DagDbWritebackRequest {
        knowledge_class: Some("finding".to_owned()),
        ..writeback_request.clone()
    };
    let mutated_knowledge_class_relay = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &mutated_knowledge_class_relay_request,
            Some(signature.clone()),
            Some(lifecycle_signature.clone()),
            Some(continuation_signature.clone()),
        ))
        .await
        .expect("mutated knowledge class relay response");
    assert_eq!(
        mutated_knowledge_class_relay.status(),
        StatusCode::FORBIDDEN,
        "a writeback signature must not authorize a mutated knowledge_class"
    );
    let mutated_knowledge_class_relay_body: DagDbErrorEnvelope =
        response_json(mutated_knowledge_class_relay).await;
    assert_eq!(
        mutated_knowledge_class_relay_body.error_code,
        "provenance_denied"
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_metadata_relay,
        "mutated knowledge_class relay must not persist DAG DB receipts"
    );
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before_metadata_relay,
        "mutated knowledge_class relay must not persist DAG DB memory rows"
    );

    let record_accepted_before_writeback =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await;
    let approval_counts_before_writeback =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let writeback_response = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request,
            Some(signature.clone()),
            Some(lifecycle_signature.clone()),
            Some(continuation_signature.clone()),
        ))
        .await
        .expect("writeback response");
    assert_eq!(writeback_response.status(), StatusCode::OK);
    let writeback_body: JsonValue = response_json(writeback_response).await;
    assert!(!writeback_body["receipt_hash"].as_str().unwrap().is_empty());
    assert_no_forbidden_material(&writeback_body.to_string());
    let receipts_after = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    assert!(
        receipts_after > receipts_before,
        "writeback must append at least one dagdb_receipts row"
    );
    assert!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_record_accepted").await
            > record_accepted_before_writeback,
        "writeback success must append a durable dagdb_record_accepted receipt"
    );
    assert_approval_counts_increased(
        approval_counts_before_writeback,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "writeback success",
    );
    let lifecycle_state = lifecycle_d5_state(
        &db.pool,
        &writeback_request.context_packet_id,
        &writeback_request.validation_report_id,
    )
    .await;
    assert_eq!(lifecycle_state.terminal_state, "accepted");
    assert_eq!(lifecycle_state.production_lifecycle_approval, "approved");
    let continuation_state =
        continuation_d5_state(&db.pool, &writeback_request.idempotency_key).await;
    assert_eq!(continuation_state.production_lifecycle_approval, "approved");
    assert_eq!(continuation_state.later_retrieval_status, "pending");
    assert!(
        continuation_state
            .blocker_refs_text
            .contains("production_lifecycle_approval_approved"),
        "continuation must persist an approved readiness ref"
    );
    assert!(
        !continuation_state.blocker_refs_text.contains("deferred"),
        "continuation must not persist deferred blockers after approved writeback"
    );

    // Q3-S1 typed knowledge writebacks: an invalid class fails closed before any
    // persistence, an empty summary on a knowledge class is rejected, a valid
    // class persists a searchable `knowledge:<class>` keyword, and a classless
    // writeback persists no knowledge keyword (telemetry unchanged).
    let receipts_before_invalid_class = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let invalid_class_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-invalid-class".to_owned(),
        answer_hash: h(0x84),
        route_id: h(0x94),
        validation_report_id: h(0xb4),
        summary_text: Some("Has a summary but an invalid class".to_owned()),
        knowledge_class: Some("rumor".to_owned()),
        ..writeback_request.clone()
    };
    let invalid_class_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &invalid_class_request,
            Some(signature.clone()),
        ))
        .await
        .expect("invalid knowledge class response");
    assert_eq!(
        invalid_class_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let invalid_class_body: DagDbErrorEnvelope = response_json(invalid_class_response).await;
    assert_eq!(invalid_class_body.error_code, "invalid_knowledge_class");
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_invalid_class,
        "invalid knowledge class must fail before DAG DB persistence"
    );

    let empty_summary_class_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-empty-summary-class".to_owned(),
        answer_hash: h(0x85),
        route_id: h(0x95),
        validation_report_id: h(0xb5),
        summary_text: Some("   ".to_owned()),
        knowledge_class: Some("finding".to_owned()),
        ..writeback_request.clone()
    };
    let empty_summary_class_response = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &empty_summary_class_request,
            Some(signature.clone()),
        ))
        .await
        .expect("empty summary knowledge class response");
    assert_eq!(
        empty_summary_class_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let empty_summary_class_body: DagDbErrorEnvelope =
        response_json(empty_summary_class_response).await;
    assert_eq!(
        empty_summary_class_body.error_code,
        "knowledge_class_requires_summary"
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_invalid_class,
        "empty-summary knowledge writeback must fail before DAG DB persistence"
    );

    let knowledge_writeback_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-knowledge-finding".to_owned(),
        answer_hash: h(0x86),
        route_id: h(0x96),
        validation_report_id: h(0xb6),
        summary_text: Some("Typed knowledge writeback persisted a finding".to_owned()),
        knowledge_class: Some("finding".to_owned()),
        ..writeback_request.clone()
    };
    let knowledge_selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&knowledge_writeback_request)
            .expect("knowledge selection request"),
    )
    .await
    .expect("knowledge selection for signature");
    let knowledge_signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&knowledge_selection.selection).expect("knowledge payload hash"),
    )
    .expect("knowledge signature");
    let (knowledge_lifecycle_signature, knowledge_continuation_signature) =
        writeback_d5_signatures(&keypair, &knowledge_writeback_request);
    let knowledge_writeback_response = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &knowledge_writeback_request,
            Some(knowledge_signature),
            Some(knowledge_lifecycle_signature),
            Some(knowledge_continuation_signature),
        ))
        .await
        .expect("knowledge writeback response");
    assert_eq!(knowledge_writeback_response.status(), StatusCode::OK);
    let knowledge_keywords = memory_keyword_texts(
        &db.pool,
        TENANT_ID,
        NAMESPACE,
        &knowledge_selection.selection,
    )
    .await;
    assert!(
        knowledge_keywords
            .iter()
            .any(|keyword| keyword == "knowledge:finding"),
        "knowledge writeback must persist a searchable knowledge:finding keyword, got {knowledge_keywords:?}"
    );

    let classless_writeback_request = DagDbWritebackRequest {
        idempotency_key: "idem-writeback-classless".to_owned(),
        answer_hash: h(0x87),
        route_id: h(0x97),
        validation_report_id: h(0xb7),
        summary_text: Some("Plain telemetry writeback with no knowledge class".to_owned()),
        knowledge_class: None,
        ..writeback_request.clone()
    };
    let classless_selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&classless_writeback_request)
            .expect("classless selection request"),
    )
    .await
    .expect("classless selection for signature");
    let classless_signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&classless_selection.selection).expect("classless payload hash"),
    )
    .expect("classless signature");
    let (classless_lifecycle_signature, classless_continuation_signature) =
        writeback_d5_signatures(&keypair, &classless_writeback_request);
    let classless_writeback_response = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &classless_writeback_request,
            Some(classless_signature),
            Some(classless_lifecycle_signature),
            Some(classless_continuation_signature),
        ))
        .await
        .expect("classless writeback response");
    assert_eq!(classless_writeback_response.status(), StatusCode::OK);
    let classless_keywords = memory_keyword_texts(
        &db.pool,
        TENANT_ID,
        NAMESPACE,
        &classless_selection.selection,
    )
    .await;
    assert!(
        !classless_keywords
            .iter()
            .any(|keyword| keyword.starts_with("knowledge:")),
        "classless writeback must not persist any knowledge keyword, got {classless_keywords:?}"
    );

    // The layered writeback target must be bound into the signed usage-event
    // payload: a relayed signature minted for one writeback shape must not
    // authorize first-submission of a mutated layer target, and a signature
    // minted for a flat writeback must not authorize adding a layer target.
    let layered_writeback_request = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-layered-1".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x83),
        route_id: h(0x93),
        context_packet_id: writeback_request.context_packet_id.clone(),
        validation_report_id: h(0xb3),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: Some("auto".to_owned()),
        target_layer_path: Some("root/codex/runtime".to_owned()),
        target_layer_depth: Some(2),
        target_layer_reason: Some("layer target binding regression".to_owned()),
    };
    let layered_selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&layered_writeback_request)
            .expect("layered selection request"),
    )
    .await
    .expect("layered selection for signature");
    let layered_signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&layered_selection.selection).expect("layered payload hash"),
    )
    .expect("layered signature");
    let (layered_lifecycle_signature, layered_continuation_signature) =
        writeback_d5_signatures(&keypair, &layered_writeback_request);
    let flat_shape_request = DagDbWritebackRequest {
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
        ..layered_writeback_request.clone()
    };
    let flat_shape_selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&flat_shape_request).expect("flat selection request"),
    )
    .await
    .expect("flat selection for signature");
    let flat_shape_signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&flat_shape_selection.selection).expect("flat payload hash"),
    )
    .expect("flat shape signature");

    let receipts_before_layer_relay = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let mutated_layer_relay_request = DagDbWritebackRequest {
        target_layer_path: Some("root/codex/exfiltration".to_owned()),
        target_layer_reason: Some("mutated layer target relay".to_owned()),
        ..layered_writeback_request.clone()
    };
    let mutated_layer_relay = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &mutated_layer_relay_request,
            Some(layered_signature.clone()),
            Some(layered_lifecycle_signature.clone()),
            Some(layered_continuation_signature.clone()),
        ))
        .await
        .expect("mutated layer relay response");
    assert_eq!(
        mutated_layer_relay.status(),
        StatusCode::FORBIDDEN,
        "a writeback signature must not authorize a mutated layer target"
    );
    let mutated_layer_relay_body: DagDbErrorEnvelope = response_json(mutated_layer_relay).await;
    assert_eq!(mutated_layer_relay_body.error_code, "provenance_denied");
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_layer_relay,
        "mutated layer target relay must not persist DAG DB rows"
    );

    let layered_escalation = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &layered_writeback_request,
            Some(flat_shape_signature),
            Some(layered_lifecycle_signature.clone()),
            Some(layered_continuation_signature.clone()),
        ))
        .await
        .expect("layered escalation response");
    assert_eq!(
        layered_escalation.status(),
        StatusCode::FORBIDDEN,
        "a flat writeback signature must not authorize adding a layer target"
    );
    let layered_escalation_body: DagDbErrorEnvelope = response_json(layered_escalation).await;
    assert_eq!(layered_escalation_body.error_code, "provenance_denied");
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_layer_relay,
        "flat signature layer escalation must not persist DAG DB rows"
    );

    let layered_writeback = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &layered_writeback_request,
            Some(layered_signature),
            Some(layered_lifecycle_signature),
            Some(layered_continuation_signature),
        ))
        .await
        .expect("layered writeback response");
    assert_eq!(
        layered_writeback.status(),
        StatusCode::OK,
        "a correctly signed layered writeback must still persist"
    );
    let layered_writeback_body: JsonValue = response_json(layered_writeback).await;
    assert_eq!(
        layered_writeback_body["layered_writeback_status"],
        "layer_target_recorded"
    );
    assert_eq!(
        layered_writeback_body["target_layer_path"],
        "root/codex/runtime"
    );
    assert!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await > receipts_before_layer_relay,
        "signed layered writeback must append DAG DB rows"
    );

    insert_session_user(&db.pool, BEARER, EXPORTER_DID, TENANT_ID).await;
    let export = export_request();
    assert_eq!(
        export.requester_did, EXPORTER_DID,
        "export success/replay/conflict must use the requester with active Export consent"
    );
    let receipts_before_missing_export_signature =
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let signature_failures_before_missing_export_signature =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let idempotency_before_missing_export_signature =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await;
    let export_rows_before_missing_export_signature =
        export_row_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let missing_export_signature = app
        .clone()
        .oneshot(scoped_post(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &export,
            None,
        ))
        .await
        .expect("missing export signature response");
    assert_eq!(missing_export_signature.status(), StatusCode::BAD_REQUEST);
    let missing_export_signature_body: DagDbErrorEnvelope =
        response_json(missing_export_signature).await;
    assert_eq!(
        missing_export_signature_body.error_code,
        "write_signature_required"
    );
    assert_eq!(
        missing_export_signature_body
            .operational_event_type
            .as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_missing_export_signature + 1,
        "missing export signature must append one durable operational receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_missing_export_signature + 1,
        "missing export signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await,
        idempotency_before_missing_export_signature,
        "missing export signature must fail before idempotency reservation"
    );
    assert_eq!(
        export_row_count(&db.pool, TENANT_ID, NAMESPACE).await,
        export_rows_before_missing_export_signature,
        "missing export signature must not mutate export data"
    );

    let receipts_before_export_consent_gap = receipt_count(&db.pool, TENANT_ID, NAMESPACE).await;
    let approval_denied_before_export_consent_gap =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await;
    let idempotency_before_export_consent_gap =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await;
    let export_completed_before_export_consent_gap =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await;
    let export_consent_gap_signatures = export_signatures(&db.pool, &keypair, &export).await;
    let export_response = app
        .clone()
        .oneshot(scoped_post_with_export_finality_signature(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &export,
            Some(export_consent_gap_signatures.write_signature),
            Some(export_consent_gap_signatures.finality_signature),
        ))
        .await
        .expect("export response");
    assert_eq!(
        export_response.status(),
        StatusCode::FORBIDDEN,
        "writeback consent must not authorize export"
    );
    let export_body: DagDbErrorEnvelope = response_json(export_response).await;
    assert_eq!(export_body.error_code, "consent_denied");
    assert_eq!(
        export_body.operational_event_type.as_deref(),
        Some("dagdb_approval_denied")
    );
    assert_no_forbidden_material(&export_body.message);
    assert_eq!(
        receipt_count(&db.pool, TENANT_ID, NAMESPACE).await,
        receipts_before_export_consent_gap + 1,
        "writeback consent must only append an operational denial receipt"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_approval_denied").await,
        approval_denied_before_export_consent_gap + 1,
        "writeback consent gap must persist dagdb_approval_denied for export"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await,
        export_completed_before_export_consent_gap,
        "writeback consent must not append dagdb_export_completed receipts"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await,
        idempotency_before_export_consent_gap,
        "writeback consent must not leave an export idempotency reservation"
    );

    ctx.install_gatekeeper_profile(
        active_import_export_consent_engine(),
        identity_registry_with_finality_authority(&keypair),
    );
    let forged_export_signatures = export_signatures(&db.pool, &keypair, &export).await;
    let signature_failures_before_forged_export =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await;
    let idempotency_before_forged_export =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await;
    let forged_export_material = DagDbExportRequest {
        idempotency_key: "idem-export-forged-signature".to_owned(),
        include_preview_context: true,
        ..export.clone()
    };
    let forged_export_response = app
        .clone()
        .oneshot(scoped_post_with_export_finality_signature(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &forged_export_material,
            Some(forged_export_signatures.write_signature),
            Some(forged_export_signatures.finality_signature),
        ))
        .await
        .expect("forged export signature response");
    assert_eq!(forged_export_response.status(), StatusCode::FORBIDDEN);
    let forged_export_body: DagDbErrorEnvelope = response_json(forged_export_response).await;
    assert_eq!(forged_export_body.error_code, "provenance_denied");
    assert_eq!(
        forged_export_body.operational_event_type.as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_signature_failure").await,
        signature_failures_before_forged_export + 1,
        "forged export signature must persist dagdb_signature_failure"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await,
        idempotency_before_forged_export,
        "forged export signature must clean its idempotency reservation"
    );
    let idempotency_before_export_success =
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await;
    let export_completed_before_success =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await;
    let approval_counts_before_export_success =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let export_success_signatures = export_signatures(&db.pool, &keypair, &export).await;
    let export_success = app
        .clone()
        .oneshot(scoped_post_with_export_finality_signature(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &export,
            Some(export_success_signatures.write_signature.clone()),
            Some(export_success_signatures.finality_signature.clone()),
        ))
        .await
        .expect("export success response");
    assert_eq!(export_success.status(), StatusCode::OK);
    let export_success_body: JsonValue = response_json(export_success).await;
    assert_eq!(export_success_body["export_status"], "built");
    assert_eq!(export_success_body["idempotency_status"], "stored");
    assert!(
        export_success_body["exported_record_count"]
            .as_u64()
            .unwrap_or_default()
            > 0,
        "export must read real DAG DB rows"
    );
    assert_eq!(
        idempotency_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb.export").await,
        idempotency_before_export_success + 1,
        "export success must store one idempotency response"
    );
    assert!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await
            > export_completed_before_success,
        "export success must append a durable dagdb_export_completed receipt"
    );
    assert_approval_counts_increased(
        approval_counts_before_export_success,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "export success",
    );
    let replay_detected_before_export_replay =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_replay_detected").await;
    let export_completed_before_export_replay =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await;
    let approval_counts_before_export_replay =
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await;
    let export_replay = app
        .clone()
        .oneshot(scoped_post_with_export_finality_signature(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &export,
            Some(export_success_signatures.write_signature),
            Some(export_success_signatures.finality_signature),
        ))
        .await
        .expect("export replay response");
    assert_eq!(export_replay.status(), StatusCode::OK);
    let export_replay_body: JsonValue = response_json(export_replay).await;
    let mut expected_export_replay_body = export_success_body.clone();
    expected_export_replay_body["idempotency_status"] = JsonValue::String("replayed".to_owned());
    assert_eq!(export_replay_body, expected_export_replay_body);
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_replay_detected").await,
        replay_detected_before_export_replay + 1,
        "idempotent export replay must persist dagdb_replay_detected"
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_export_completed").await,
        export_completed_before_export_replay,
        "idempotent export replay must not append duplicate dagdb_export_completed receipts"
    );
    assert_approval_counts_unchanged(
        approval_counts_before_export_replay,
        approval_event_counts(&db.pool, TENANT_ID, NAMESPACE).await,
        "idempotent export replay",
    );
    let changed_export_material = DagDbExportRequest {
        include_preview_context: true,
        ..export.clone()
    };
    let idempotency_conflicts_before_changed_export =
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_idempotency_conflict").await;
    let changed_export_signatures =
        export_signatures(&db.pool, &keypair, &changed_export_material).await;
    let changed_export_response = app
        .clone()
        .oneshot(scoped_post_with_export_finality_signature(
            "/api/v1/dag-db/export",
            "dagdb:export",
            &changed_export_material,
            Some(changed_export_signatures.write_signature),
            Some(changed_export_signatures.finality_signature),
        ))
        .await
        .expect("changed export idempotency response");
    assert_eq!(changed_export_response.status(), StatusCode::CONFLICT);
    let changed_export_body: DagDbErrorEnvelope = response_json(changed_export_response).await;
    assert_eq!(changed_export_body.error_code, "idempotency_key_conflict");
    assert_eq!(
        changed_export_body.operational_event_type.as_deref(),
        Some("dagdb_idempotency_conflict")
    );
    assert_eq!(
        receipt_event_count(&db.pool, TENANT_ID, NAMESPACE, "dagdb_idempotency_conflict").await,
        idempotency_conflicts_before_changed_export + 1,
        "changed export material must persist dagdb_idempotency_conflict"
    );
    insert_session_user(&db.pool, BEARER, AGENT_DID, TENANT_ID).await;

    let writeback_request_tenant_mismatch = DagDbWritebackRequest {
        tenant_id: "tenant-b".to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-tenant-mismatch".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x83),
        route_id: h(0x93),
        context_packet_id: h(0xa2),
        validation_report_id: h(0xb3),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let tenant_mismatch = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request_tenant_mismatch,
            Some(signature.clone()),
            Some(lifecycle_signature.clone()),
            Some(continuation_signature.clone()),
        ))
        .await
        .expect("tenant mismatch writeback response");
    assert_eq!(tenant_mismatch.status(), StatusCode::FORBIDDEN);
    let tenant_mismatch_body: DagDbErrorEnvelope = response_json(tenant_mismatch).await;
    assert_eq!(tenant_mismatch_body.error_code, "tenant_scope_mismatch");
    assert_eq!(
        tenant_mismatch_body.operational_event_type.as_deref(),
        Some("dagdb_rls_tenant_violation")
    );

    let bad_council = DagDbCouncilDecisionRequest {
        expires_at: "not-an-hlc".to_owned(),
        ..council_decision_request()
    };
    let council_error = app
        .clone()
        .oneshot(council_post(
            TENANT_ID,
            NAMESPACE,
            "dagdb:council_decision:tenant-a:primary",
            &bad_council,
        ))
        .await
        .expect("council error response");
    assert_eq!(council_error.status(), StatusCode::BAD_REQUEST);
    let council_error_body: DagDbErrorEnvelope = response_json(council_error).await;
    assert_eq!(council_error_body.error_code, "invalid_request_shape");
    assert_no_forbidden_material(&council_error_body.message);

    let writeback_request_metadata = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-metadata".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x83),
        route_id: h(0x93),
        context_packet_id: h(0xa2),
        validation_report_id: h(0xb3),
        summary_text: Some("fn raw_payload() {}".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let selection_metadata = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&writeback_request_metadata)
            .expect("selection request for metadata writeback"),
    )
    .await
    .expect("selection for metadata rejection signature");
    let metadata_signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&selection_metadata.selection).expect("hash"),
    )
    .expect("signature");
    let (metadata_lifecycle_signature, metadata_continuation_signature) =
        writeback_d5_signatures(&keypair, &writeback_request_metadata);
    let metadata_rejected = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request_metadata,
            Some(metadata_signature),
            Some(metadata_lifecycle_signature),
            Some(metadata_continuation_signature),
        ))
        .await
        .expect("metadata rejected response");
    let metadata_status = metadata_rejected.status();
    let metadata_body: DagDbErrorEnvelope = response_json(metadata_rejected).await;
    assert_eq!(
        metadata_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unexpected error envelope: {metadata_body:?}"
    );
    assert_eq!(metadata_body.error_code, "metadata_rejected");

    let writeback_request_provenance = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-provenance".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x84),
        route_id: h(0x94),
        context_packet_id: h(0xa3),
        validation_report_id: h(0xb4),
        summary_text: Some("Safe answer summary".to_owned()),
        citation_hashes: None,
        safety_score_id: None,
        keyword_texts: None,
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let forged_hash = Hash256::digest(b"forged-payload");
    let forged_signature =
        sign_write_payload(&keypair, forged_hash.as_bytes()).expect("forged signature");
    let (provenance_lifecycle_signature, provenance_continuation_signature) =
        writeback_d5_signatures(&keypair, &writeback_request_provenance);
    let provenance_denied = app
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request_provenance,
            Some(forged_signature),
            Some(provenance_lifecycle_signature),
            Some(provenance_continuation_signature),
        ))
        .await
        .expect("provenance denied response");
    assert_eq!(provenance_denied.status(), StatusCode::FORBIDDEN);
    let provenance_body: DagDbErrorEnvelope = response_json(provenance_denied).await;
    assert_eq!(provenance_body.error_code, "provenance_denied");

    // Regression (header-trust gap + synthetic scaffold success): the standalone
    // router resolves the live integration context override in this process, so
    // valid bearer calls must return typed persisted route DTOs while forged
    // bearer calls fail closed.
    let standalone = dagdb_router::<()>();
    let fixtures = dagdb_fixtures();
    let trust_check = trust_check_request();
    let forged_trust = standalone
        .clone()
        .oneshot(scoped_post_with_bearer(
            FORGED_BEARER,
            "/api/v1/dag-db/trust-check",
            "dagdb:trust_check",
            &trust_check,
            None,
        ))
        .await
        .expect("forged bearer trust-check response");
    assert_unauthenticated_without_standalone_session(forged_trust).await;

    let live_trust = standalone
        .clone()
        .oneshot(scoped_post_with_bearer(
            BEARER,
            "/api/v1/dag-db/trust-check",
            "dagdb:trust_check",
            &trust_check,
            None,
        ))
        .await
        .expect("live bearer trust-check response");
    assert_success_schema(live_trust, "dagdb_trust_check_response_v1").await;

    let intake: DagDbIntakeRequest = dagdb_fixture(&fixtures, "intake");
    let live_intake = standalone
        .clone()
        .oneshot(scoped_post_with_bearer(
            BEARER,
            "/api/v1/dag-db/intake",
            "dagdb:intake",
            &intake,
            None,
        ))
        .await
        .expect("live bearer intake response");
    assert_success_schema(live_intake, "dagdb_intake_response_v1").await;

    let route: DagDbRouteRequest = dagdb_fixture(&fixtures, "route");
    let live_route = standalone
        .clone()
        .oneshot(scoped_post_with_bearer(
            BEARER,
            "/api/v1/dag-db/route",
            "dagdb:route",
            &route,
            None,
        ))
        .await
        .expect("live bearer route response");
    assert_standalone_route_requires_write_signature(live_route).await;

    let validation: DagDbValidateRequest = dagdb_fixture(&fixtures, "validate");
    let live_validation = standalone
        .clone()
        .oneshot(scoped_post_with_bearer(
            BEARER,
            "/api/v1/dag-db/validate",
            "dagdb:validate",
            &validation,
            None,
        ))
        .await
        .expect("live bearer validate response");
    assert_success_schema(live_validation, "dagdb_validate_response_v1").await;

    let receipt: DagDbReceiptLookupRequest = dagdb_fixture(&fixtures, "receipt_lookup");
    let live_receipt = standalone
        .clone()
        .oneshot(scoped_get(
            &format!(
                "/api/v1/dag-db/receipts/{}?tenant_id={}&namespace={}&include_body=true",
                receipt.receipt_hash, receipt.tenant_id, receipt.namespace
            ),
            "dagdb:receipt_lookup",
        ))
        .await
        .expect("live bearer receipt lookup response");
    assert_not_found(live_receipt).await;

    let catalog: DagDbCatalogLookupRequest = dagdb_fixture(&fixtures, "catalog_lookup");
    let live_catalog = standalone
        .clone()
        .oneshot(scoped_get(
            &format!(
                "/api/v1/dag-db/catalog/{}?tenant_id={}&namespace={}&include_children=true&include_routes=true",
                catalog.catalog_id, catalog.tenant_id, catalog.namespace
            ),
            "dagdb:catalog_lookup",
        ))
        .await
        .expect("live bearer catalog lookup response");
    assert_not_found(live_catalog).await;

    let route_lookup: DagDbRouteLookupRequest = dagdb_fixture(&fixtures, "route_lookup");
    let live_route_lookup = standalone
        .clone()
        .oneshot(scoped_get(
            &format!(
                "/api/v1/dag-db/routes/{}?tenant_id={}&namespace={}&include_memory_refs=true&include_validation=true",
                route_lookup.route_id, route_lookup.tenant_id, route_lookup.namespace
            ),
            "dagdb:route_lookup",
        ))
        .await
        .expect("live bearer route lookup response");
    assert_not_found(live_route_lookup).await;

    let forged_council = standalone
        .clone()
        .oneshot(council_post_with_bearer(
            FORGED_BEARER,
            TENANT_ID,
            NAMESPACE,
            "dagdb:council_decision:tenant-a:primary",
            &council_decision_request(),
        ))
        .await
        .expect("forged bearer council response");
    assert_unauthenticated_without_standalone_session(forged_council).await;

    let live_council = standalone
        .clone()
        .oneshot(council_post_with_bearer(
            BEARER,
            TENANT_ID,
            NAMESPACE,
            "dagdb:council_decision:tenant-a:primary",
            &council_decision_request(),
        ))
        .await
        .expect("live bearer council response");
    assert_success_schema(live_council, "dagdb_council_decision_response_v1").await;

    db.cleanup().await;
}

#[tokio::test]
async fn writeback_rolls_back_usage_event_when_d5_continuation_persistence_fails() {
    let Some(database_url) = configured_database_url(
        "writeback_rolls_back_usage_event_when_d5_continuation_persistence_fails",
    ) else {
        return;
    };
    let db = TestDb::new("writeback_atomicity", &database_url).await;

    let keypair = KeyPair::generate();
    let ctx = Arc::new(DagDbRouteContext::from_pool(Some(db.pool.clone())));
    set_route_context_for_integration_tests(ctx.clone());
    ctx.install_gatekeeper_profile(
        active_import_export_consent_engine(),
        identity_registry_with_finality_authority(&keypair),
    );
    insert_session_user(&db.pool, BEARER, AGENT_DID, TENANT_ID).await;

    let app = build_router(AppState::new(
        Some(db.pool.clone()),
        Arc::new(RwLock::new(LocalDidRegistry::new())),
    ));

    let import_request = DagDbImportRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-import-writeback-atomicity".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        source_hash: h(0x01),
        requester_did: AGENT_DID.to_owned(),
        import_report: base_report(),
    };
    let import_signatures = import_signatures(&db.pool, &keypair, &import_request).await;
    let import_success = app
        .clone()
        .oneshot(scoped_post_with_import_finality_signature(
            "/api/v1/dag-db/import",
            "dagdb:import",
            &import_request,
            Some(import_signatures.write_signature),
            Some(import_signatures.finality_signature),
        ))
        .await
        .expect("seed import response");
    assert_eq!(import_success.status(), StatusCode::OK);

    let writeback_request = DagDbWritebackRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-writeback-d5-continuation-conflict".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        parent_memory_ids: vec![h(0x10)],
        answer_hash: h(0x88),
        route_id: h(0x98),
        context_packet_id: h(0xa8),
        validation_report_id: h(0xb8),
        summary_text: Some("Atomic writeback regression summary".to_owned()),
        citation_hashes: Some(vec![h(0xc8)]),
        safety_score_id: None,
        keyword_texts: Some(vec!["atomicity".to_owned()]),
        knowledge_class: None,
        layered_mode: None,
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
    };
    let selection = build_persistent_graph_context_selection(
        &db.pool,
        &selection_request_from_writeback(&writeback_request)
            .expect("selection request for atomic writeback"),
    )
    .await
    .expect("selection for atomic writeback signature");
    let signature = sign_write_payload(
        &keypair,
        &usage_event_payload_hash(&selection.selection).expect("atomic writeback payload hash"),
    )
    .expect("atomic writeback signature");
    let (lifecycle_signature, continuation_signature) =
        writeback_d5_signatures(&keypair, &writeback_request);

    insert_conflicting_continuation_record(&db.pool, &writeback_request).await;
    let memory_objects_before = memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await;

    let response = app
        .clone()
        .oneshot(scoped_post_with_d5_signatures(
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            &writeback_request,
            Some(signature),
            Some(lifecycle_signature),
            Some(continuation_signature),
        ))
        .await
        .expect("atomic writeback failure response");
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "conflicting D5 continuation row must fail writeback persistence"
    );
    let body: DagDbErrorEnvelope = response_json(response).await;
    assert_eq!(body.error_code, "metadata_rejected");
    assert_eq!(
        memory_object_count(&db.pool, TENANT_ID, NAMESPACE).await,
        memory_objects_before,
        "D5 continuation failure must roll back the main writeback usage-event memory"
    );

    db.cleanup().await;
}

fn default_route_approval_signature_binds_request_and_purpose() {
    let keypair = KeyPair::generate();
    let request = DagDbRouteRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-route-binding-smoke".to_owned(),
        requesting_agent_did: AGENT_DID.to_owned(),
        task_signature_hash: h(0x41),
        approved_scope_hash: h(0x42),
        token_budget: 2_048,
        start_catalog_id: None,
        requested_memory_ids: Some(vec!["memory-binding-smoke".to_owned()]),
        credential_id: None,
    };
    let route_id = default_route_id(&request);
    let proposed = default_route_record(&request, &route_id, "operator_deferred");
    let approval_hash_hex = canonical_default_route_approval_payload_hash(
        &proposed,
        &request.requesting_agent_did,
        &request.idempotency_key,
        FINALITY_AUTHORITY_DID,
        DEFAULT_ROUTE_FINALITY_PURPOSE,
        fixed_approval_timestamp(),
    )
    .expect("canonical route approval hash");
    let approval_hash = decode_hex_hash(&approval_hash_hex);
    let signature = sign_write_payload(&keypair, &approval_hash).expect("route approval signature");
    let registry = IdentityRegistry::default()
        .with_public_key(FINALITY_AUTHORITY_DID, *keypair.public_key().as_bytes());
    assert!(
        verify_write_signature(
            &registry,
            &approval_hash,
            &signature,
            FINALITY_AUTHORITY_DID
        )
        .expect("signature verifies")
    );

    let wrong_request_hash = decode_hex_hash(
        &canonical_default_route_approval_payload_hash(
            &proposed,
            &request.requesting_agent_did,
            "other-idempotency-key",
            FINALITY_AUTHORITY_DID,
            DEFAULT_ROUTE_FINALITY_PURPOSE,
            fixed_approval_timestamp(),
        )
        .expect("wrong request hash"),
    );
    assert!(
        !verify_write_signature(
            &registry,
            &wrong_request_hash,
            &signature,
            FINALITY_AUTHORITY_DID
        )
        .expect("wrong request signature check")
    );

    let wrong_purpose_hash = decode_hex_hash(
        &canonical_default_route_approval_payload_hash(
            &proposed,
            &request.requesting_agent_did,
            &request.idempotency_key,
            FINALITY_AUTHORITY_DID,
            CONTEXT_PACKET_FINALITY_PURPOSE,
            fixed_approval_timestamp(),
        )
        .expect("wrong purpose hash"),
    );
    assert!(
        !verify_write_signature(
            &registry,
            &wrong_purpose_hash,
            &signature,
            FINALITY_AUTHORITY_DID
        )
        .expect("wrong purpose signature check")
    );
}

fn trust_check_request() -> DagDbTrustCheckRequest {
    DagDbTrustCheckRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-trust-check-standalone".to_owned(),
        agent_did: AGENT_DID.to_owned(),
        operator_did: "did:exo:operator".to_owned(),
        model_name: "governed-model".to_owned(),
        model_version: "1.0".to_owned(),
        provider_or_builder: "exochain".to_owned(),
        requested_action: "memory:read".to_owned(),
        requested_scope_hash: h(0xd0),
        purpose: ConsentPurpose::TrustCheck,
        autonomy_level: "supervised".to_owned(),
        nonce: h(0xd1),
        expires_at: "2000:0".to_owned(),
        signature: "trust-check-signature".to_owned(),
        checkpoint_hash: None,
        attestation_hash: None,
        evidence_receipt_hashes: None,
        prior_trust_receipt_hash: None,
    }
}

fn council_decision_request() -> DagDbCouncilDecisionRequest {
    DagDbCouncilDecisionRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-council-integration".to_owned(),
        subject_kind: SubjectKind::Memory,
        subject_id: Hash256::from_bytes([0xf0; 32]).to_string(),
        requested_action: "memory:routable".to_owned(),
        approved_scope_hash: Hash256::from_bytes([0x12; 32]).to_string(),
        risk_class: RiskClass::R3,
        approver_did: "did:exo:council".to_owned(),
        decision_source: DecisionSource::Human,
        decision_status: CouncilDecisionStatus::Approved,
        reason_code: "operator_approved".to_owned(),
        created_at: "1000:0".to_owned(),
        expires_at: "2000:0".to_owned(),
        validation_report_id: None,
        route_id: None,
        context_packet_id: None,
        notes_text: Some("Safe approval notes".to_owned()),
    }
}

fn council_post<T>(
    tenant_header: &str,
    namespace_header: &str,
    authority_scope: &str,
    body: &T,
) -> Request<Body>
where
    T: serde::Serialize,
{
    council_post_with_bearer(
        BEARER,
        tenant_header,
        namespace_header,
        authority_scope,
        body,
    )
}

fn council_post_with_bearer<T>(
    bearer: &str,
    tenant_header: &str,
    namespace_header: &str,
    authority_scope: &str,
    body: &T,
) -> Request<Body>
where
    T: serde::Serialize,
{
    Request::builder()
        .method("POST")
        .uri("/api/v1/dag-db/council/decision")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header("x-exo-tenant-id", tenant_header)
        .header("x-exo-namespace", namespace_header)
        .header("x-exo-authority-scope", authority_scope)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("request")
}

fn export_request() -> DagDbExportRequest {
    DagDbExportRequest {
        tenant_id: TENANT_ID.to_owned(),
        namespace: NAMESPACE.to_owned(),
        idempotency_key: "idem-export-integration".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        requester_did: EXPORTER_DID.to_owned(),
        included_memory_ids: Vec::new(),
        included_graph_styles: Vec::new(),
        included_writeback_idempotency_keys: Vec::new(),
        source_commit_or_repo_ref: Some("c706242d36f1c275e05d8a132778491da08f61c7".to_owned()),
        include_preview_context: false,
    }
}

fn identity_registry_with_finality_authority(keypair: &KeyPair) -> IdentityRegistry {
    IdentityRegistry::default()
        .with_public_key(AGENT_DID, *keypair.public_key().as_bytes())
        .with_public_key(EXPORTER_DID, *keypair.public_key().as_bytes())
        .with_public_key(FINALITY_AUTHORITY_DID, *keypair.public_key().as_bytes())
        .with_governed_role(FINALITY_AUTHORITY_DID, GovernedRoleName::Operator)
}

fn active_consent_engine() -> ConsentEngine {
    ConsentEngine::default()
        .with_bailment(
            TENANT_ID,
            BailmentState::Active {
                bailor: exo_core::Did::new("did:exo:bailor").expect("bailor"),
                bailee: exo_core::Did::new(AGENT_DID).expect("bailee"),
                scope: "dag-db:writeback".into(),
            },
        )
        .with_consent_record(DagDbConsentRecord {
            tenant_id: TENANT_ID.to_owned(),
            agent_did: AGENT_DID.to_owned(),
            purpose: ConsentPurpose::Writeback,
            active: true,
        })
        .with_consent_record(DagDbConsentRecord {
            tenant_id: TENANT_ID.to_owned(),
            agent_did: EXPORTER_DID.to_owned(),
            purpose: ConsentPurpose::Writeback,
            active: true,
        })
}

fn active_import_export_consent_engine() -> ConsentEngine {
    active_consent_engine()
        .with_consent_record(DagDbConsentRecord {
            tenant_id: TENANT_ID.to_owned(),
            agent_did: AGENT_DID.to_owned(),
            purpose: ConsentPurpose::Import,
            active: true,
        })
        .with_consent_record(DagDbConsentRecord {
            tenant_id: TENANT_ID.to_owned(),
            agent_did: EXPORTER_DID.to_owned(),
            purpose: ConsentPurpose::Export,
            active: true,
        })
}

struct DefaultRouteSignatures {
    write_signature: String,
    approval_signature: String,
}

fn default_route_signatures(
    keypair: &KeyPair,
    request: &DagDbRouteRequest,
) -> DefaultRouteSignatures {
    let route_id = default_route_id(request);
    let proposed = default_route_record(request, &route_id, "operator_deferred");
    let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
        &proposed,
        &request.requesting_agent_did,
        &request.idempotency_key,
        FINALITY_AUTHORITY_DID,
        DEFAULT_ROUTE_FINALITY_PURPOSE,
        fixed_approval_timestamp(),
    )
    .expect("default route approval payload hash");
    let approval_payload_hash = decode_hex_hash(&approval_payload_hash_hex);
    let approval_signature = sign_write_payload(keypair, &approval_payload_hash)
        .expect("default route approval signature");
    let updated_at = proposed.updated_at.clone();
    let accepted = accept_default_route_record(
        &proposed,
        &default_route_acceptance_evidence(
            request,
            &route_id,
            &approval_signature,
            &approval_payload_hash_hex,
        ),
        updated_at,
    )
    .expect("accepted default route record");
    let write_signature = sign_write_payload(
        keypair,
        &default_route_payload_hash(&accepted).expect("default route payload hash"),
    )
    .expect("default route signature");
    DefaultRouteSignatures {
        write_signature,
        approval_signature,
    }
}

fn default_route_id(request: &DagDbRouteRequest) -> String {
    gateway_hash_hex(
        "dagdb.gateway.route",
        &(
            &gateway_route_request_hash(request),
            &request.task_signature_hash,
        ),
    )
}

fn default_route_record(
    request: &DagDbRouteRequest,
    route_id: &str,
    approval_status: &str,
) -> DefaultRouteRecord {
    let selected_memory_refs =
        sorted_strings(request.requested_memory_ids.clone().unwrap_or_default())
            .into_iter()
            .map(|memory_id| DefaultRouteMemoryRef {
                latest_receipt_hash: gateway_hash_hex(
                    "dagdb.gateway.default_route.memory_receipt",
                    &(&route_id, &memory_id),
                ),
                citation_ref: gateway_hash_hex(
                    "dagdb.gateway.default_route.citation",
                    &(&route_id, &memory_id),
                ),
                validation_status: "passed".to_owned(),
                memory_id,
            })
            .collect();
    DefaultRouteRecord {
        schema_version: DEFAULT_ROUTE_SCHEMA_VERSION.to_owned(),
        route_id: route_id.to_owned(),
        request_id: request.idempotency_key.clone(),
        tenant_id: request.tenant_id.clone(),
        project_id: request.namespace.clone(),
        memory_namespace: request.namespace.clone(),
        status: DefaultRouteStatus::Active,
        route_source: DefaultRouteSource::Persisted,
        policy_ref: request.approved_scope_hash.clone(),
        freshness_ref: request.task_signature_hash.clone(),
        policy_allowed: true,
        freshness_status: RouteFreshnessStatus::Current,
        invalidated: false,
        production_default_route_approval_status: approval_status.to_owned(),
        packet_quality_review_status: approval_status.to_owned(),
        selected_memory_refs,
        created_at: gateway_hash_hex("dagdb.route.created_at", &request.idempotency_key),
        updated_at: gateway_hash_hex("dagdb.route.updated_at", &request.idempotency_key),
    }
}

fn default_route_acceptance_evidence(
    request: &DagDbRouteRequest,
    route_id: &str,
    approval_signature: &str,
    approval_payload_hash_hex: &str,
) -> DefaultRouteAcceptanceEvidence {
    let approved_at = fixed_approval_timestamp().to_owned();
    DefaultRouteAcceptanceEvidence {
        production_default_route_approval_ref: format!(
            "external-production-approval:{}",
            gateway_hash_hex(
                "dagdb.gateway.default_route.external_production_approval",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &request.requesting_agent_did,
                    route_id,
                    &request.idempotency_key,
                    FINALITY_AUTHORITY_DID,
                    approval_payload_hash_hex,
                    approval_signature,
                    &approved_at,
                ),
            )
        ),
        packet_quality_review_ref: format!(
            "external-packet-quality-review:{}",
            gateway_hash_hex(
                "dagdb.gateway.default_route.packet_quality",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    route_id,
                    &request.task_signature_hash,
                    FINALITY_AUTHORITY_DID,
                    approval_payload_hash_hex,
                ),
            )
        ),
        finality_ref: format!(
            "external-finality:{}",
            gateway_hash_hex(
                "dagdb.gateway.default_route.external_finality",
                &(
                    &gateway_hash_hex(
                        "dagdb.gateway.receipt",
                        &("dagdb.route", gateway_route_request_hash(request)),
                    ),
                    &request.idempotency_key,
                    FINALITY_AUTHORITY_DID,
                    approval_signature,
                    approval_payload_hash_hex,
                    &approved_at,
                ),
            )
        ),
        tenant_id: request.tenant_id.clone(),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: route_id.to_owned(),
        route_purpose: DEFAULT_ROUTE_FINALITY_PURPOSE.to_owned(),
        request_id: request.idempotency_key.clone(),
        payload_hash: approval_payload_hash_hex.to_owned(),
        receipt_payload_hash: approval_payload_hash_hex.to_owned(),
        authority_did: FINALITY_AUTHORITY_DID.to_owned(),
        authority_signature: approval_signature.to_owned(),
        approved_at,
    }
}

struct ContextPacketSignatures {
    write_signature: String,
    approval_signature: String,
}

async fn context_packet_signatures(
    pool: &PgPool,
    keypair: &KeyPair,
    request: &DagDbContextPacketRequest,
) -> ContextPacketSignatures {
    let material = context_packet_record_material(pool, request, "operator_deferred").await;
    let approval_payload_hash_hex = canonical_context_packet_approval_payload_hash(
        &material.record,
        &request.requesting_agent_did,
        &material.record.idempotency_key,
        FINALITY_AUTHORITY_DID,
        CONTEXT_PACKET_FINALITY_PURPOSE,
        fixed_approval_timestamp(),
    )
    .expect("context packet approval payload hash");
    let approval_payload_hash = decode_hex_hash(&approval_payload_hash_hex);
    let approval_signature = sign_write_payload(keypair, &approval_payload_hash)
        .expect("context packet approval signature");
    let accepted = accept_context_packet_record(
        &material.record,
        &context_packet_acceptance_evidence(
            request,
            &material.packet_hash,
            &material.receipt_hash,
            &approval_signature,
            &approval_payload_hash_hex,
        ),
    )
    .expect("accepted context packet record");
    let write_signature = sign_write_payload(
        keypair,
        &context_packet_record_payload_hash(&accepted).expect("context packet payload hash"),
    )
    .expect("context packet signature");
    ContextPacketSignatures {
        write_signature,
        approval_signature,
    }
}

struct ContextPacketRecordMaterial {
    record: exo_dag_db_domain::context_packet_persistence::ContextPacketRecord,
    packet_hash: String,
    receipt_hash: String,
}

async fn context_packet_record_material(
    pool: &PgPool,
    request: &DagDbContextPacketRequest,
    approval_status: &str,
) -> ContextPacketRecordMaterial {
    let selection_request = selection_request_for_context_packet(request);
    let selection = build_persistent_graph_context_selection(pool, &selection_request)
        .await
        .expect("context packet selection for signature");
    assert!(
        !selection.selection.selected_memory_refs.is_empty(),
        "context packet signature helper requires selected memory refs"
    );
    let build_request = DagDbGraphContextPacketBuildRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.request_id.clone(),
        task: graph_context_packet_task(request),
        task_hash: request.task_hash.clone(),
        audit_id: request.idempotency_key.clone(),
        token_budget: selection.selection.token_budget,
        selection: selection.selection.clone(),
        import_tracking_status: None,
    };
    let packet = build_graph_context_packet(&build_request).expect("graph context packet");
    let selected_memory_ids = sorted_strings(
        packet
            .selected_memory_refs
            .iter()
            .map(|memory_ref| memory_ref.memory_id.clone())
            .collect(),
    );
    let selected_edge_ids = sorted_strings(
        packet
            .selected_graph_edges
            .iter()
            .map(|edge| edge.graph_edge_id.clone())
            .collect(),
    );
    let source_proof_refs = sorted_strings(
        packet
            .selected_memory_refs
            .iter()
            .map(|memory_ref| {
                selection
                    .selected_memory_receipt_hashes
                    .get(&memory_ref.memory_id)
                    .cloned()
                    .expect("selected memory receipt hash")
            })
            .collect(),
    );
    let binding = ContextPacketRouteBinding {
        route_id: request.route_id.clone(),
        tenant_id: request.tenant_id.clone(),
        project_id: request.namespace.clone(),
        memory_namespace: request.namespace.clone(),
        production_default_route_approval_status: approval_status.to_owned(),
        packet_quality_review_status: approval_status.to_owned(),
        route_freshness_status: PacketFreshnessStatus::Current,
    };
    let record = build_context_packet_record(
        &binding,
        ContextPacketRequest {
            packet_id: packet.packet_hash.clone(),
            query_hash: request.task_hash.clone(),
            selected_memory_ids,
            selected_edge_ids,
            token_budget: request.token_budget,
            token_estimate: packet.packet_metrics.selected_token_estimate,
            citation_coverage_bp: 10_000,
            validation_coverage_bp: 10_000,
            source_proof_refs,
            context_quality: DefaultContextQuality::UsableContext,
            freshness_status: PacketFreshnessStatus::Current,
            validation_status: PacketValidationStatus::Passed,
            persistence_status: PacketPersistenceStatus::ProofBound,
            fallback_reason: None,
            raw_body_present: false,
            created_at: gateway_hash_hex(
                "dagdb.context_packet.created_at",
                &request.idempotency_key,
            ),
        },
    )
    .expect("context packet record");
    let receipt_hash = gateway_hash_hex(
        "dagdb.gateway.receipt",
        &("dagdb.context_packet", packet.packet_hash.as_str()),
    );
    ContextPacketRecordMaterial {
        record,
        packet_hash: packet.packet_hash,
        receipt_hash,
    }
}

fn context_packet_acceptance_evidence(
    request: &DagDbContextPacketRequest,
    packet_hash: &str,
    receipt_hash: &str,
    approval_signature: &str,
    approval_payload_hash_hex: &str,
) -> ContextPacketAcceptanceEvidence {
    let approved_at = fixed_approval_timestamp().to_owned();
    ContextPacketAcceptanceEvidence {
        production_default_route_approval_ref: format!(
            "external-production-approval:{}",
            gateway_hash_hex(
                "dagdb.gateway.context_packet.external_production_approval",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &request.requesting_agent_did,
                    &request.route_id,
                    packet_hash,
                    &request.request_id,
                    FINALITY_AUTHORITY_DID,
                    approval_payload_hash_hex,
                    approval_signature,
                    &approved_at,
                ),
            )
        ),
        packet_quality_review_ref: format!(
            "external-packet-quality-review:{}",
            gateway_hash_hex(
                "dagdb.gateway.context_packet.quality_review",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    packet_hash,
                    packet_hash,
                    FINALITY_AUTHORITY_DID,
                    approval_payload_hash_hex,
                ),
            )
        ),
        finality_ref: format!(
            "external-finality:{}",
            gateway_hash_hex(
                "dagdb.gateway.context_packet.external_finality",
                &(
                    receipt_hash,
                    &request.idempotency_key,
                    FINALITY_AUTHORITY_DID,
                    approval_signature,
                    approval_payload_hash_hex,
                    &approved_at,
                ),
            )
        ),
        tenant_id: request.tenant_id.clone(),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: request.route_id.clone(),
        packet_id: packet_hash.to_owned(),
        route_purpose: CONTEXT_PACKET_FINALITY_PURPOSE.to_owned(),
        request_id: canonical_idempotency_key(
            &request.route_id,
            &request.task_hash,
            request.token_budget,
        ),
        payload_hash: approval_payload_hash_hex.to_owned(),
        receipt_payload_hash: approval_payload_hash_hex.to_owned(),
        authority_did: FINALITY_AUTHORITY_DID.to_owned(),
        authority_signature: approval_signature.to_owned(),
        approved_at,
    }
}

fn writeback_d5_signatures(keypair: &KeyPair, request: &DagDbWritebackRequest) -> (String, String) {
    let lifecycle_signature = sign_write_payload(
        keypair,
        &writeback_lifecycle_approval_payload_hash(
            request,
            FINALITY_AUTHORITY_DID,
            fixed_lifecycle_approval_timestamp(),
        )
        .expect("writeback lifecycle approval payload hash"),
    )
    .expect("writeback lifecycle signature");
    let continuation_signature = sign_write_payload(
        keypair,
        &writeback_continuation_approval_payload_hash(
            request,
            FINALITY_AUTHORITY_DID,
            fixed_continuation_approval_timestamp(),
        )
        .expect("writeback continuation approval payload hash"),
    )
    .expect("writeback continuation signature");
    (lifecycle_signature, continuation_signature)
}

struct OperationSignatures {
    write_signature: String,
    finality_signature: String,
}

async fn import_signatures(
    pool: &PgPool,
    keypair: &KeyPair,
    request: &DagDbImportRequest,
) -> OperationSignatures {
    let authorization_payload_hash = import_authorization_payload_hash(pool, request).await;
    let write_signature = sign_write_payload(keypair, authorization_payload_hash.as_bytes())
        .expect("import signature");
    let finality_payload_hash = import_finality_payload_hash(request, authorization_payload_hash);
    let finality_signature = sign_write_payload(keypair, &finality_payload_hash)
        .expect("import finality approval signature");
    OperationSignatures {
        write_signature,
        finality_signature,
    }
}

async fn export_signatures(
    pool: &PgPool,
    keypair: &KeyPair,
    request: &DagDbExportRequest,
) -> OperationSignatures {
    let authorization_payload_hash = export_authorization_payload_hash(pool, request).await;
    let write_signature = sign_write_payload(keypair, authorization_payload_hash.as_bytes())
        .expect("export signature");
    let finality_payload_hash = export_finality_payload_hash(request, authorization_payload_hash);
    let finality_signature = sign_write_payload(keypair, &finality_payload_hash)
        .expect("export finality approval signature");
    OperationSignatures {
        write_signature,
        finality_signature,
    }
}

async fn import_authorization_payload_hash(pool: &PgPool, request: &DagDbImportRequest) -> Hash256 {
    let selection =
        build_persistent_graph_context_selection(pool, &selection_request_for_import(request))
            .await
            .expect("selection for import signature");
    Hash256::from_bytes(
        usage_event_payload_hash(&selection.selection).expect("import payload hash"),
    )
}

async fn export_authorization_payload_hash(pool: &PgPool, request: &DagDbExportRequest) -> Hash256 {
    let selection =
        build_persistent_graph_context_selection(pool, &selection_request_for_export(request))
            .await
            .expect("selection for export signature");
    Hash256::from_bytes(
        usage_event_payload_hash(&selection.selection).expect("export payload hash"),
    )
}

fn import_finality_payload_hash(
    request: &DagDbImportRequest,
    authorization_payload_hash: Hash256,
) -> [u8; 32] {
    decode_hex_hash(&gateway_hash_hex(
        "dagdb.gateway.import.external_finality",
        &(
            &request.tenant_id,
            &request.namespace,
            &request.requester_did,
            &request.idempotency_key,
            &request.db_set_version,
            &request.source_hash,
            authorization_payload_hash.to_string(),
            FINALITY_AUTHORITY_DID,
            fixed_approval_timestamp(),
        ),
    ))
}

fn export_finality_payload_hash(
    request: &DagDbExportRequest,
    authorization_payload_hash: Hash256,
) -> [u8; 32] {
    decode_hex_hash(&gateway_hash_hex(
        "dagdb.gateway.export.external_finality",
        &(
            &request.tenant_id,
            &request.namespace,
            &request.requester_did,
            &request.idempotency_key,
            &request.db_set_version,
            export_request_hash(request).to_string(),
            authorization_payload_hash.to_string(),
            FINALITY_AUTHORITY_DID,
            fixed_approval_timestamp(),
        ),
    ))
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

fn selection_request_for_export(
    request: &DagDbExportRequest,
) -> exo_api::dagdb::DagDbGraphContextSelectionRequest {
    let max_memory_refs = u32::try_from(request.included_memory_ids.len())
        .unwrap_or(u32::MAX)
        .clamp(1, 64);
    exo_api::dagdb::DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.idempotency_key.clone(),
        task: format!("export:{}", request.db_set_version),
        task_hash: export_request_hash(request).to_string(),
        token_budget: 2_048,
        max_memory_refs,
        catalog_hints: request.included_graph_styles.clone(),
        requested_memory_ids: request.included_memory_ids.clone(),
        force_revalidate: false,
    }
}

fn export_request_hash(request: &DagDbExportRequest) -> Hash256 {
    let body = serde_json::to_value(request).expect("export request json");
    let mut canonical_body = Vec::new();
    ciborium::ser::into_writer(&body, &mut canonical_body).expect("canonical export request");
    RequestHashMaterial {
        route_name: "dagdb.export".to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        canonical_redacted_request_body: canonical_body,
    }
    .hash()
    .expect("export request hash")
}

fn selection_request_for_context_packet(
    request: &DagDbContextPacketRequest,
) -> exo_api::dagdb::DagDbGraphContextSelectionRequest {
    let task = graph_context_packet_task(request);
    let token_budget = if request.token_budget == 0 {
        exo_dag_db_postgres::graph_context_selection::task_budget_tokens(&task)
    } else {
        request.token_budget
    };
    exo_api::dagdb::DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.request_id.clone(),
        task,
        task_hash: request.task_hash.clone(),
        token_budget,
        max_memory_refs: token_budget.min(64),
        catalog_hints: Vec::new(),
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

fn graph_context_packet_task(request: &DagDbContextPacketRequest) -> String {
    request
        .task
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("route:{}", request.route_id))
}

fn gateway_route_request_hash(request: &DagDbRouteRequest) -> Hash256 {
    let body = serde_json::to_value(request).expect("route request json");
    let mut canonical_body = Vec::new();
    ciborium::ser::into_writer(&body, &mut canonical_body).expect("canonical route request");
    RequestHashMaterial {
        route_name: "dagdb.route".to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        canonical_redacted_request_body: canonical_body,
    }
    .hash()
    .expect("route request hash")
}

fn gateway_hash_hex<T: serde::Serialize>(domain: &str, value: &T) -> String {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(domain, value), &mut bytes).expect("gateway hash material");
    Hash256::digest(&bytes).to_string()
}

fn fixed_approval_timestamp() -> &'static str {
    "2026-06-20T00:00:00Z"
}

fn fixed_lifecycle_approval_timestamp() -> &'static str {
    fixed_approval_timestamp()
}

fn fixed_continuation_approval_timestamp() -> &'static str {
    "2026-06-20T00:00:01Z"
}

fn decode_hex_hash(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("hex hash")
        .try_into()
        .expect("32-byte hash")
}

async fn insert_conflicting_continuation_record(pool: &PgPool, request: &DagDbWritebackRequest) {
    let target_memory_id = writeback_target_memory_id_for_test(request);
    let idempotency_key = writeback_continuation_idempotency_key(request);
    let mut memory_ids = request.parent_memory_ids.clone();
    memory_ids.push(target_memory_id.clone());
    let memory_refs: Vec<JsonValue> = sorted_strings(memory_ids)
        .into_iter()
        .map(|memory_id| {
            json!({
                "tenant_id": request.tenant_id,
                "project_id": request.namespace,
                "memory_namespace": request.namespace,
                "memory_id": memory_id
            })
        })
        .collect();
    sqlx::query(
        "INSERT INTO dagdb_continuation_records \
         (continuation_id, task_id, tenant_id, project_id, memory_namespace, summary_ref, \
          memory_refs, blocker_refs, validation_refs, expiry_epoch_seconds, later_retrieval_status, \
          production_lifecycle_approval, idempotency_key, record_body, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', 'approved', $11, $12, $13)",
    )
    .bind(gateway_hash_hex(
        "dagdb.test.conflicting_continuation",
        &request.idempotency_key,
    ))
    .bind(&request.idempotency_key)
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(&request.namespace)
    .bind(&target_memory_id)
    .bind(json!(memory_refs))
    .bind(json!(["production_lifecycle_approval_approved"]))
    .bind(json!([request.validation_report_id]))
    .bind(4_102_444_800_i64)
    .bind(&idempotency_key)
    .bind(json!({
        "test_conflict": "different continuation body",
        "idempotency_key": idempotency_key
    }))
    .bind("test-conflicting-continuation")
    .execute(pool)
    .await
    .expect("insert conflicting continuation row");
}

fn writeback_continuation_idempotency_key(request: &DagDbWritebackRequest) -> String {
    let target_memory_id = writeback_target_memory_id_for_test(request);
    let mut memory_ids = request.parent_memory_ids.clone();
    memory_ids.push(target_memory_id.clone());
    let memory_hash = sha256_hex(sorted_strings(memory_ids).join(",").as_bytes());
    format!(
        "{}:{}:{}:{}:{}:{}",
        request.tenant_id,
        request.namespace,
        request.namespace,
        request.idempotency_key,
        target_memory_id,
        memory_hash
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn writeback_target_memory_id_for_test(request: &DagDbWritebackRequest) -> String {
    gateway_hash_hex(
        "dagdb.gateway.writeback.target_memory",
        &(&request.idempotency_key, &request.answer_hash),
    )
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

struct DefaultRouteD5State {
    production_default_route_approval_status: String,
    packet_quality_review_status: String,
    selected_memory_ref_count: i32,
}

async fn default_route_d5_state(pool: &PgPool, route_id: &str) -> DefaultRouteD5State {
    let row = sqlx::query(
        "SELECT production_default_route_approval_status, \
                packet_quality_review_status, selected_memory_ref_count \
         FROM dagdb_default_routes \
         WHERE tenant_id = $1 AND project_id = $2 AND memory_namespace = $3 AND route_id = $4",
    )
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .bind(route_id)
    .fetch_one(pool)
    .await
    .expect("default route D5 row");
    DefaultRouteD5State {
        production_default_route_approval_status: row
            .get("production_default_route_approval_status"),
        packet_quality_review_status: row.get("packet_quality_review_status"),
        selected_memory_ref_count: row.get("selected_memory_ref_count"),
    }
}

async fn default_route_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM dagdb_default_routes \
         WHERE tenant_id = $1 AND project_id = $2 AND memory_namespace = $3",
    )
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .fetch_one(pool)
    .await
    .expect("default route count")
}

struct ContextPacketD5State {
    production_default_route_approval_status: String,
    packet_quality_review_status: String,
    context_quality: String,
    validation_status: String,
    selected_memory_count: i32,
}

async fn context_packet_d5_state(pool: &PgPool, packet_id: &str) -> ContextPacketD5State {
    let row = sqlx::query(
        "SELECT production_default_route_approval_status, \
                packet_quality_review_status, context_quality, validation_status, \
                jsonb_array_length(selected_memory_ids) AS selected_memory_count \
         FROM dagdb_context_packet_records \
         WHERE packet_id = $1 AND tenant_id = $2 AND project_id = $3 AND memory_namespace = $4",
    )
    .bind(packet_id)
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .fetch_one(pool)
    .await
    .expect("context packet D5 row");
    ContextPacketD5State {
        production_default_route_approval_status: row
            .get("production_default_route_approval_status"),
        packet_quality_review_status: row.get("packet_quality_review_status"),
        context_quality: row.get("context_quality"),
        validation_status: row.get("validation_status"),
        selected_memory_count: row.get("selected_memory_count"),
    }
}

async fn context_packet_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM dagdb_context_packet_records \
         WHERE tenant_id = $1 AND project_id = $2 AND memory_namespace = $3",
    )
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .fetch_one(pool)
    .await
    .expect("context packet count")
}

struct LifecycleD5State {
    terminal_state: String,
    production_lifecycle_approval: String,
}

async fn lifecycle_d5_state(
    pool: &PgPool,
    source_packet_id: &str,
    source_receipt_id: &str,
) -> LifecycleD5State {
    let row = sqlx::query(
        "SELECT terminal_state, production_lifecycle_approval \
         FROM dagdb_lifecycle_actions \
         WHERE tenant_id = $1 AND project_id = $2 AND memory_namespace = $3 \
           AND source_packet_id = $4 AND source_receipt_id = $5",
    )
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .bind(source_packet_id)
    .bind(source_receipt_id)
    .fetch_one(pool)
    .await
    .expect("lifecycle D5 row");
    LifecycleD5State {
        terminal_state: row.get("terminal_state"),
        production_lifecycle_approval: row.get("production_lifecycle_approval"),
    }
}

struct ContinuationD5State {
    later_retrieval_status: String,
    production_lifecycle_approval: String,
    blocker_refs_text: String,
}

async fn continuation_d5_state(pool: &PgPool, task_id: &str) -> ContinuationD5State {
    let row = sqlx::query(
        "SELECT later_retrieval_status, production_lifecycle_approval, \
                blocker_refs::TEXT AS blocker_refs_text \
         FROM dagdb_continuation_records \
         WHERE tenant_id = $1 AND project_id = $2 AND memory_namespace = $3 AND task_id = $4",
    )
    .bind(TENANT_ID)
    .bind(NAMESPACE)
    .bind(NAMESPACE)
    .bind(task_id)
    .fetch_one(pool)
    .await
    .expect("continuation D5 row");
    ContinuationD5State {
        later_retrieval_status: row.get("later_retrieval_status"),
        production_lifecycle_approval: row.get("production_lifecycle_approval"),
        blocker_refs_text: row.get("blocker_refs_text"),
    }
}

/// Collect the persisted keyword texts for the usage-event memory row a
/// writeback created, keyed by the selection's deterministic `task_hash`
/// (the usage memory row stores `source_hash = decode(task_hash, 'hex')`).
async fn memory_keyword_texts(
    pool: &PgPool,
    tenant_id: &str,
    namespace: &str,
    selection: &exo_api::dagdb::DagDbGraphContextSelectionResponse,
) -> Vec<String> {
    let source_hash = hex::decode(&selection.task_hash).expect("decode selection task hash");
    let rows: Vec<JsonValue> = sqlx::query_scalar(
        "SELECT keywords FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 AND source_hash = $3",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(source_hash)
    .fetch_all(pool)
    .await
    .expect("fetch usage memory keywords");
    rows.iter()
        .flat_map(|keywords| keywords.as_array().cloned().unwrap_or_default())
        .filter_map(|keyword| {
            keyword
                .get("text")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        })
        .collect()
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

async fn assert_export_schema_tables_present(pool: &PgPool) {
    let missing_tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM (VALUES ('dagdb_exports'), ('dagdb_export_challenges')) AS required(name) \
         WHERE to_regclass(format('%I.%I', current_schema(), name)) IS NULL ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .expect("check export schema tables");
    assert!(
        missing_tables.is_empty(),
        "fresh integration schema is missing export tables: {missing_tables:?}"
    );
}

async fn receipt_event_count(
    pool: &PgPool,
    tenant_id: &str,
    namespace: &str,
    event_type: &str,
) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_receipts \
         WHERE tenant_id = $1 AND namespace = $2 AND event_type = $3",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count receipt event type")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApprovalEventCounts {
    request_submitted: i64,
    granted: i64,
}

async fn approval_event_counts(
    pool: &PgPool,
    tenant_id: &str,
    namespace: &str,
) -> ApprovalEventCounts {
    ApprovalEventCounts {
        request_submitted: receipt_event_count(
            pool,
            tenant_id,
            namespace,
            "dagdb_approval_request_submitted",
        )
        .await,
        granted: receipt_event_count(pool, tenant_id, namespace, "dagdb_approval_granted").await,
    }
}

fn assert_approval_counts_increased(
    before: ApprovalEventCounts,
    after: ApprovalEventCounts,
    operation: &str,
) {
    assert!(
        after.request_submitted > before.request_submitted,
        "{operation} must append a durable dagdb_approval_request_submitted receipt"
    );
    assert!(
        after.granted > before.granted,
        "{operation} must append a durable dagdb_approval_granted receipt"
    );
}

fn assert_approval_counts_unchanged(
    before: ApprovalEventCounts,
    after: ApprovalEventCounts,
    operation: &str,
) {
    assert_eq!(
        after.request_submitted, before.request_submitted,
        "{operation} must not append duplicate dagdb_approval_request_submitted receipts"
    );
    assert_eq!(
        after.granted, before.granted,
        "{operation} must not append duplicate dagdb_approval_granted receipts"
    );
}

async fn memory_object_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_memory_objects WHERE tenant_id = $1 AND namespace = $2",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_one(pool)
    .await
    .expect("count memory objects")
}

async fn export_row_count(pool: &PgPool, tenant_id: &str, namespace: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dagdb_exports WHERE tenant_id = $1 AND namespace = $2")
        .bind(tenant_id)
        .bind(namespace)
        .fetch_one(pool)
        .await
        .expect("count export rows")
}

async fn idempotency_count(
    pool: &PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .fetch_one(pool)
    .await
    .expect("count idempotency keys")
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

fn configured_database_url(test_name: &str) -> Option<String> {
    match std::env::var(KG_IMPORT_DATABASE_URL_ENV) {
        Ok(database_url) => Some(database_url),
        Err(std::env::VarError::NotPresent) => {
            eprintln!(
                "skipping {test_name}: {KG_IMPORT_DATABASE_URL_ENV} is unset; live DAG DB gateway integration coverage not run"
            );
            None
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{KG_IMPORT_DATABASE_URL_ENV} must be valid Unicode")
        }
    }
}

fn scoped_post<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    scoped_post_with_bearer(BEARER, path, action, body, write_signature)
}

fn scoped_post_with_default_route_signature<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
    default_route_approval_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut request = scoped_post_with_bearer(BEARER, path, action, body, write_signature);
    let headers = request.headers_mut();
    if let Some(signature) = default_route_approval_signature {
        headers.insert(
            "x-exo-default-route-approval-signature",
            signature
                .parse()
                .expect("default route approval signature header"),
        );
    }
    headers.insert(
        "x-exo-default-route-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("default route approval DID header"),
    );
    headers.insert(
        "x-exo-default-route-approval-timestamp",
        fixed_approval_timestamp()
            .parse()
            .expect("default route approval timestamp header"),
    );
    request
}

fn scoped_post_with_context_packet_signature<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
    context_packet_approval_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut request = scoped_post_with_bearer(BEARER, path, action, body, write_signature);
    let headers = request.headers_mut();
    if let Some(signature) = context_packet_approval_signature {
        headers.insert(
            "x-exo-context-packet-approval-signature",
            signature
                .parse()
                .expect("context packet approval signature header"),
        );
    }
    headers.insert(
        "x-exo-context-packet-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("context packet approval DID header"),
    );
    headers.insert(
        "x-exo-context-packet-approval-timestamp",
        fixed_approval_timestamp()
            .parse()
            .expect("context packet approval timestamp header"),
    );
    request
}

fn scoped_post_with_import_finality_signature<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
    import_approval_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut request = scoped_post_with_bearer(BEARER, path, action, body, write_signature);
    let headers = request.headers_mut();
    if let Some(signature) = import_approval_signature {
        headers.insert(
            "x-exo-import-approval-signature",
            signature.parse().expect("import approval signature header"),
        );
    }
    headers.insert(
        "x-exo-import-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("import approval DID header"),
    );
    headers.insert(
        "x-exo-import-approval-timestamp",
        fixed_approval_timestamp()
            .parse()
            .expect("import approval timestamp header"),
    );
    request
}

fn scoped_post_with_export_finality_signature<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
    export_approval_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut request = scoped_post_with_bearer(BEARER, path, action, body, write_signature);
    let headers = request.headers_mut();
    if let Some(signature) = export_approval_signature {
        headers.insert(
            "x-exo-export-approval-signature",
            signature.parse().expect("export approval signature header"),
        );
    }
    headers.insert(
        "x-exo-export-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("export approval DID header"),
    );
    headers.insert(
        "x-exo-export-approval-timestamp",
        fixed_approval_timestamp()
            .parse()
            .expect("export approval timestamp header"),
    );
    request
}

fn scoped_post_with_d5_signatures<T>(
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
    lifecycle_signature: Option<String>,
    continuation_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut request = scoped_post_with_bearer(BEARER, path, action, body, write_signature);
    let headers = request.headers_mut();
    if let Some(signature) = lifecycle_signature {
        headers.insert(
            "x-exo-lifecycle-signature",
            signature.parse().expect("lifecycle signature header"),
        );
    }
    if let Some(signature) = continuation_signature {
        headers.insert(
            "x-exo-continuation-signature",
            signature.parse().expect("continuation signature header"),
        );
    }
    headers.insert(
        "x-exo-lifecycle-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("lifecycle approval DID header"),
    );
    headers.insert(
        "x-exo-continuation-approval-did",
        FINALITY_AUTHORITY_DID
            .parse()
            .expect("continuation approval DID header"),
    );
    headers.insert(
        "x-exo-lifecycle-approval-timestamp",
        fixed_lifecycle_approval_timestamp()
            .parse()
            .expect("lifecycle approval timestamp header"),
    );
    headers.insert(
        "x-exo-continuation-approval-timestamp",
        fixed_continuation_approval_timestamp()
            .parse()
            .expect("continuation approval timestamp header"),
    );
    request
}

fn scoped_post_with_bearer<T>(
    bearer: &str,
    path: &str,
    action: &str,
    body: &T,
    write_signature: Option<String>,
) -> Request<Body>
where
    T: serde::Serialize,
{
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header("x-exo-tenant-id", TENANT_ID)
        .header("x-exo-namespace", NAMESPACE)
        .header(
            "x-exo-authority-scope",
            format!("{action}:{TENANT_ID}:{NAMESPACE}"),
        )
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(signature) = write_signature {
        builder = builder.header("x-exo-write-signature", signature);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("request")
}

fn scoped_get(path: &str, action: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .header("x-exo-tenant-id", TENANT_ID)
        .header("x-exo-namespace", NAMESPACE)
        .header(
            "x-exo-authority-scope",
            format!("{action}:{TENANT_ID}:{NAMESPACE}"),
        )
        .body(Body::empty())
        .expect("request")
}

async fn insert_session_user(pool: &PgPool, token: &str, did: &str, tenant_id: &str) {
    sqlx::query("DELETE FROM sessions WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await
        .expect("delete test session");
    sqlx::query("DELETE FROM users WHERE did = $1")
        .bind(did)
        .execute(pool)
        .await
        .expect("delete test user");
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

fn unauthenticated_post<T>(path: &str, body: &T) -> Request<Body>
where
    T: serde::Serialize,
{
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("request")
}

async fn response_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

async fn assert_success_schema(response: axum::response::Response, expected_schema: &str) {
    let status = response.status();
    let body: JsonValue = response_json(response).await;
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "mounted live DAG DB route must return typed persisted success: {body:?}"
    );
    assert_eq!(body["schema_version"], expected_schema);
}

async fn assert_not_found(response: axum::response::Response) {
    let status = response.status();
    let body: DagDbErrorEnvelope = response_json(response).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "mounted live DAG DB lookup must return typed not_found for absent rows: {body:?}"
    );
    assert_eq!(body.error_code, "not_found");
    assert_no_forbidden_material(&body.message);
}

async fn assert_standalone_route_requires_write_signature(response: axum::response::Response) {
    let status = response.status();
    let body: DagDbErrorEnvelope = response_json(response).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "dagdb.route must require write signature instead of returning scaffold success: {body:?}"
    );
    assert_eq!(body.error_code, "write_signature_required");
    assert_eq!(
        body.message,
        "DAG DB route persistence requires x-exo-write-signature header"
    );
    assert!(!body.requires_council_review);
    assert_eq!(
        body.operational_event_type.as_deref(),
        Some("dagdb_signature_failure")
    );
    assert_no_forbidden_material(&body.message);
}

async fn assert_unauthenticated_without_standalone_session(response: axum::response::Response) {
    let status = response.status();
    let body: DagDbErrorEnvelope = response_json(response).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "standalone DAG DB router must reject forged bearer state before persistence: {body:?}"
    );
    assert_eq!(body.error_code, "unauthenticated");
    assert_no_forbidden_material(&body.message);
}

fn dagdb_fixtures() -> JsonValue {
    serde_json::from_str(include_str!(
        "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
    ))
    .expect("parse complete DAG DB fixture set")
}

fn dagdb_fixture<T>(fixtures: &JsonValue, name: &str) -> T
where
    T: DeserializeOwned,
{
    serde_json::from_value(
        fixtures
            .get("requests")
            .and_then(|requests| requests.get(name))
            .unwrap_or_else(|| panic!("missing fixture requests.{name}"))
            .clone(),
    )
    .unwrap_or_else(|err| panic!("parse fixture requests.{name}: {err}"))
}

fn assert_no_forbidden_material(payload: &str) {
    for forbidden in ["postgres://", "postgresql://", "fn raw_payload()"] {
        assert!(
            !payload.contains(forbidden),
            "response must not expose forbidden material ({forbidden})"
        );
    }
}

fn base_report() -> JsonValue {
    json!({
        "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
        "graph_root": "KnowledgeGraphs/dag-db",
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "actor_did": AGENT_DID,
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

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
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
        "actor_did": AGENT_DID,
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
