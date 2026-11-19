#![cfg(feature = "production-db")]
#![allow(clippy::expect_used, clippy::panic)]

use std::{net::TcpListener, process};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use exo_api::dagdb::{
    DagDbCatalogLookupRequest, DagDbContextPacketRequest, DagDbCouncilDecisionRequest,
    DagDbErrorEnvelope, DagDbExportRequest, DagDbImportRequest, DagDbIntakeRequest,
    DagDbReceiptLookupRequest, DagDbRouteLookupRequest, DagDbRouteRequest, DagDbTrustCheckRequest,
    DagDbValidateRequest, DagDbWritebackRequest,
};
use exo_dag_db_exchange::kg_import::{
    KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
};
use exo_dag_db_postgres::postgres::init_pool;
use exo_gateway::dagdb::{DAGDB_REST_PREFIX, dagdb_router};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::{Connection, PgConnection};
use tower::ServiceExt;

const TEST_DATABASE_URL_ENV: &str = "EXO_DAGDB_TEST_DATABASE_URL";

#[tokio::test]
async fn dagdb_cross_tenant_denies_every_live_post_route() {
    let Some(database_url) =
        configured_database_url("dagdb_cross_tenant_denies_every_live_post_route")
    else {
        return;
    };
    let schema = ScopedDagDbSchema::new("cross_tenant", database_url).await;
    let _pool = init_pool(&schema.database_url)
        .await
        .expect("DAG DB production gateway test database must initialize");
    let app = dagdb_router::<()>();
    let fixtures = fixtures();

    assert_cross_tenant_post(
        app.clone(),
        "/api/v1/dag-db/route",
        "dagdb:route",
        fixture::<DagDbRouteRequest>(&fixtures, "requests", "route"),
    )
    .await;
    assert_cross_tenant_post(
        app.clone(),
        "/api/v1/dag-db/context-packet",
        "dagdb:context_packet",
        fixture::<DagDbContextPacketRequest>(&fixtures, "requests", "context_packet"),
    )
    .await;
    assert_cross_tenant_post(
        app.clone(),
        "/api/v1/dag-db/writeback",
        "dagdb:writeback",
        fixture::<DagDbWritebackRequest>(&fixtures, "requests", "writeback"),
    )
    .await;
    assert_cross_tenant_post(
        app.clone(),
        "/api/v1/dag-db/import",
        "dagdb:import",
        import_request(),
    )
    .await;
    assert_cross_tenant_post(
        app.clone(),
        "/api/v1/dag-db/export",
        "dagdb:export",
        export_request(),
    )
    .await;
}

#[tokio::test]
async fn dagdb_default_router_returns_explicit_runtime_failure_for_every_live_route() {
    let Some(database_url) = configured_database_url(
        "dagdb_default_router_returns_explicit_runtime_failure_for_every_live_route",
    ) else {
        return;
    };
    let schema = ScopedDagDbSchema::new("route_success", database_url).await;
    let _pool = init_pool(&schema.database_url)
        .await
        .expect("DAG DB production gateway test database must initialize");
    let app = dagdb_router::<()>();
    let fixtures = fixtures();

    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/route",
        "dagdb:route",
        fixture::<DagDbRouteRequest>(&fixtures, "requests", "route"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/context-packet",
        "dagdb:context_packet",
        fixture::<DagDbContextPacketRequest>(&fixtures, "requests", "context_packet"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    // Writeback fails closed (503) with no production database pool, identically
    // to import/export — the prior synthetic 201 scaffold is gone (T6).
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/writeback",
        "dagdb:writeback",
        fixture::<DagDbWritebackRequest>(&fixtures, "requests", "writeback"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/import",
        "dagdb:import",
        import_request(),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/export",
        "dagdb:export",
        export_request(),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
}

#[tokio::test]
async fn dagdb_authorization_failures_are_stable() {
    let app = dagdb_router::<()>();
    let fixtures = fixtures();
    let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");

    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::NoAuth,
            ))
            .await
            .expect("missing auth response"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::BasicAuth,
            ))
            .await
            .expect("basic auth response"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::NoTenant,
            ))
            .await
            .expect("missing tenant response"),
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::NoNamespace,
            ))
            .await
            .expect("missing namespace response"),
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::NamespaceMismatch,
            ))
            .await
            .expect("namespace mismatch response"),
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/route",
                "dagdb:route",
                &request,
                HeaderCase::NoAuthorityScope,
            ))
            .await
            .expect("missing authority response"),
        StatusCode::FORBIDDEN,
        "authority_denied",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/import",
                "dagdb:import",
                &import_request(),
                HeaderCase::NoAuthorityScope,
            ))
            .await
            .expect("missing import authority response"),
        StatusCode::FORBIDDEN,
        "authority_denied",
    )
    .await;
    assert_error(
        app.clone()
            .oneshot(json_request_with_headers(
                "/api/v1/dag-db/export",
                "dagdb:export",
                &export_request(),
                HeaderCase::NamespaceMismatch,
            ))
            .await
            .expect("export namespace mismatch response"),
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
    )
    .await;

    assert_error(
        app.oneshot(json_request_with_headers(
            "/api/v1/dag-db/council/decision",
            "dagdb:council_decision",
            &fixture::<DagDbCouncilDecisionRequest>(&fixtures, "requests", "council_decision"),
            HeaderCase::NoAuth,
        ))
        .await
        .expect("council route authentication response"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await;
}

#[tokio::test]
async fn dagdb_full_surface_routes_fail_closed_without_database() {
    let app = dagdb_router::<()>();
    let fixtures = fixtures();

    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/intake",
        "dagdb:intake",
        fixture::<DagDbIntakeRequest>(&fixtures, "requests", "intake"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/validate",
        "dagdb:validate",
        fixture::<DagDbValidateRequest>(&fixtures, "requests", "validate"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/trust-check",
        "dagdb:trust_check",
        fixture::<DagDbTrustCheckRequest>(&fixtures, "requests", "trust_check"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    assert_post_error(
        app.clone(),
        "/api/v1/dag-db/council/decision",
        "dagdb:council_decision",
        fixture::<DagDbCouncilDecisionRequest>(&fixtures, "requests", "council_decision"),
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;

    let receipt: DagDbReceiptLookupRequest = fixture(&fixtures, "requests", "receipt_lookup");
    assert_get_error(
        app.clone(),
        &format!(
            "/api/v1/dag-db/receipts/{}?tenant_id={}&namespace={}",
            receipt.receipt_hash, receipt.tenant_id, receipt.namespace
        ),
        "dagdb:receipt_lookup",
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    let catalog: DagDbCatalogLookupRequest = fixture(&fixtures, "requests", "catalog_lookup");
    assert_get_error(
        app.clone(),
        &format!(
            "/api/v1/dag-db/catalog/{}?tenant_id={}&namespace={}",
            catalog.catalog_id, catalog.tenant_id, catalog.namespace
        ),
        "dagdb:catalog_lookup",
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
    let route: DagDbRouteLookupRequest = fixture(&fixtures, "requests", "route_lookup");
    assert_get_error(
        app,
        &format!(
            "/api/v1/dag-db/routes/{}?tenant_id={}&namespace={}",
            route.route_id, route.tenant_id, route.namespace
        ),
        "dagdb:route_lookup",
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
    )
    .await;
}

#[tokio::test]
async fn dagdb_routes_are_registered_additively_and_port_collision_has_fallback() {
    let app = dagdb_router::<()>();
    let fixtures = fixtures();
    let route: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
    let response = app
        .oneshot(scoped_json_request(
            "POST",
            &format!("{DAGDB_REST_PREFIX}/route"),
            "dagdb:route",
            "tenant-a",
            &route,
        ))
        .await
        .expect("DAG DB route response");
    assert_ne!(response.status(), StatusCode::NOT_FOUND);

    let held = TcpListener::bind("127.0.0.1:0").expect("bind held test port");
    let held_addr = held.local_addr().expect("held port addr");
    assert!(
        TcpListener::bind(held_addr).is_err(),
        "same port must report collision"
    );
    let fallback = TcpListener::bind("127.0.0.1:0").expect("bind alternate test port");
    assert_ne!(fallback.local_addr().expect("fallback addr"), held_addr);
}

async fn assert_cross_tenant_post<T>(app: axum::Router, path: &str, action: &str, body: T)
where
    T: Serialize,
{
    let response = app
        .oneshot(scoped_json_request("POST", path, action, "tenant-b", &body))
        .await
        .expect("DAG DB cross-tenant POST response");
    assert_tenant_scope_mismatch(response).await;
}

async fn assert_post_error<T>(
    app: axum::Router,
    path: &str,
    action: &str,
    body: T,
    status: StatusCode,
    error_code: &str,
) where
    T: Serialize,
{
    let response = app
        .oneshot(scoped_json_request("POST", path, action, "tenant-a", &body))
        .await
        .expect("DAG DB POST route error response");
    assert_error(response, status, error_code).await;
}

async fn assert_get_error(
    app: axum::Router,
    uri: &str,
    action: &str,
    status: StatusCode,
    error_code: &str,
) {
    let response = app
        .oneshot(scoped_get_request(uri, action, "tenant-a"))
        .await
        .expect("DAG DB GET route error response");
    assert_error(response, status, error_code).await;
}

fn scoped_json_request<T>(
    method: &str,
    uri: &str,
    action: &str,
    header_tenant: &str,
    body: &T,
) -> Request<Body>
where
    T: Serialize,
{
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer test-token")
        .header("x-exo-tenant-id", header_tenant)
        .header("x-exo-namespace", "primary")
        .header(
            "x-exo-authority-scope",
            format!("{action}:{header_tenant}:primary"),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize DAG DB request"),
        ))
        .expect("request")
}

fn scoped_get_request(uri: &str, action: &str, header_tenant: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer test-token")
        .header("x-exo-tenant-id", header_tenant)
        .header("x-exo-namespace", "primary")
        .header(
            "x-exo-authority-scope",
            format!("{action}:{header_tenant}:primary"),
        )
        .body(Body::empty())
        .expect("request")
}

#[derive(Clone, Copy)]
enum HeaderCase {
    NoAuth,
    BasicAuth,
    NoTenant,
    NoNamespace,
    NamespaceMismatch,
    NoAuthorityScope,
}

fn json_request_with_headers<T>(
    uri: &str,
    action: &str,
    body: &T,
    header_case: HeaderCase,
) -> Request<Body>
where
    T: Serialize,
{
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if !matches!(header_case, HeaderCase::NoAuth) {
        let auth = if matches!(header_case, HeaderCase::BasicAuth) {
            "Basic test"
        } else {
            "Bearer test-token"
        };
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if !matches!(header_case, HeaderCase::NoTenant) {
        builder = builder.header("x-exo-tenant-id", "tenant-a");
    }
    if !matches!(header_case, HeaderCase::NoNamespace) {
        let namespace = if matches!(header_case, HeaderCase::NamespaceMismatch) {
            "other"
        } else {
            "primary"
        };
        builder = builder.header("x-exo-namespace", namespace);
    }
    if !matches!(header_case, HeaderCase::NoAuthorityScope) {
        builder = builder.header(
            "x-exo-authority-scope",
            format!("{action}:tenant-a:primary"),
        );
    }
    builder
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize DAG DB request"),
        ))
        .expect("request")
}

async fn assert_tenant_scope_mismatch(response: axum::response::Response) {
    assert_error(response, StatusCode::FORBIDDEN, "tenant_scope_mismatch").await;
}

async fn assert_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) {
    assert_eq!(response.status(), expected_status);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error response body");
    let envelope: DagDbErrorEnvelope =
        serde_json::from_slice(&bytes).expect("DAG DB error envelope");
    assert_eq!(envelope.error_code, expected_code);
}

fn configured_database_url(test_name: &str) -> Option<String> {
    match std::env::var(TEST_DATABASE_URL_ENV) {
        Ok(database_url) => Some(database_url),
        Err(std::env::VarError::NotPresent) => {
            eprintln!(
                "skipping {test_name}: {TEST_DATABASE_URL_ENV} is unset; live DAG DB gateway integration coverage not run"
            );
            None
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{TEST_DATABASE_URL_ENV} must be valid Unicode")
        }
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

struct ScopedDagDbSchema {
    database_url: String,
    cleanup_database_url: String,
    schema: String,
}

impl ScopedDagDbSchema {
    async fn new(label: &str, cleanup_database_url: String) -> Self {
        let schema = format!("dagdb_gateway_{label}_{}", process::id());
        let mut conn = PgConnection::connect(&cleanup_database_url)
            .await
            .expect("connect to DAG DB gateway test database");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut conn)
        .await
        .expect("drop stale DAG DB gateway test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut conn)
            .await
            .expect("create DAG DB gateway test schema");
        let database_url = database_url_with_search_path(&cleanup_database_url, &schema);
        Self {
            database_url,
            cleanup_database_url,
            schema,
        }
    }
}

impl Drop for ScopedDagDbSchema {
    fn drop(&mut self) {
        let database_url = self.cleanup_database_url.clone();
        let schema = self.schema.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("create cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for DAG DB gateway schema cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop DAG DB gateway test schema");
            });
        })
        .join()
        .expect("join DAG DB gateway schema cleanup");
    }
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
    ))
    .expect("parse complete DAG DB fixture set")
}

fn import_request() -> DagDbImportRequest {
    DagDbImportRequest {
        tenant_id: "tenant-a".to_owned(),
        namespace: "primary".to_owned(),
        idempotency_key: "idem-import-1".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        source_hash: "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        requester_did: "did:exo:importer".to_owned(),
        import_report: serde_json::json!({
            "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
            "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            "graph_root": "KnowledgeGraphs/dag-db",
            "tenant_id": "tenant-a",
            "namespace": "primary",
            "actor_did": "did:exo:importer",
            "batch_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dry_run_only": true,
            "postgres_writes": false,
            "raw_markdown_included": false,
            "proposed_memory_records": [],
            "proposed_catalog_entries": [],
            "proposed_graph_nodes": [],
            "proposed_graph_edges": [],
            "proposed_required_edges": [],
            "proposed_placement_decisions": [],
            "proposed_receipt_intents": [],
            "proposed_validation_reports": [],
            "proposed_governance_reviews": [],
            "proposed_graph_view_refreshes": [],
            "proposed_route_invalidations": [],
            "proposed_subdag_boundaries": [],
            "rollback_plan": {},
            "placement_governance_summary": {},
            "review_items": [],
            "warnings": []
        }),
    }
}

fn export_request() -> DagDbExportRequest {
    DagDbExportRequest {
        tenant_id: "tenant-a".to_owned(),
        namespace: "primary".to_owned(),
        idempotency_key: "idem-export-1".to_owned(),
        db_set_version: "dag_db-project_memory_v3".to_owned(),
        requester_did: "did:exo:exporter".to_owned(),
        included_memory_ids: Vec::new(),
        included_graph_styles: Vec::new(),
        included_writeback_idempotency_keys: Vec::new(),
        source_commit_or_repo_ref: Some("c706242d36f1c275e05d8a132778491da08f61c7".to_owned()),
        include_preview_context: false,
    }
}

fn fixture<T>(fixtures: &serde_json::Value, section: &str, name: &str) -> T
where
    T: DeserializeOwned,
{
    serde_json::from_value(
        fixtures
            .get(section)
            .and_then(|section| section.get(name))
            .unwrap_or_else(|| panic!("missing fixture {section}.{name}"))
            .clone(),
    )
    .unwrap_or_else(|err| panic!("parse fixture {section}.{name}: {err}"))
}
