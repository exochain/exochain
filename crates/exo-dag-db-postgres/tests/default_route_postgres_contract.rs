#![cfg(feature = "postgres")]
#![allow(clippy::expect_used)]

use std::process;

use exo_dag_db_postgres::{
    default_route::{
        DEFAULT_ROUTE_SCHEMA_VERSION, DefaultRouteMemoryRef, DefaultRouteRecord,
        DefaultRouteSource, DefaultRouteStatus, RouteFreshnessStatus,
    },
    postgres::{
        DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL, DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL,
        DAGDB_SCHEMA_SQL, default_route::persist_default_route,
    },
};
use serde_json::Value;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};

fn accepted_route() -> DefaultRouteRecord {
    DefaultRouteRecord {
        schema_version: DEFAULT_ROUTE_SCHEMA_VERSION.to_owned(),
        route_id: "route-default-accepted-001".to_owned(),
        request_id: "request-default-route-001".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        memory_namespace: "primary".to_owned(),
        status: DefaultRouteStatus::Active,
        route_source: DefaultRouteSource::Persisted,
        policy_ref: "policy-proof-001".to_owned(),
        freshness_ref: "freshness-proof-001".to_owned(),
        policy_allowed: true,
        freshness_status: RouteFreshnessStatus::Current,
        invalidated: false,
        production_default_route_approval_status: "accepted".to_owned(),
        packet_quality_review_status: "accepted".to_owned(),
        selected_memory_refs: vec![DefaultRouteMemoryRef {
            memory_id: "memory-default-route-001".to_owned(),
            latest_receipt_hash: "receipt-default-route-001".to_owned(),
            validation_status: "passed".to_owned(),
            citation_ref: "citation-default-route-001".to_owned(),
        }],
        created_at: "2026-06-09T00:00:00Z".to_owned(),
        updated_at: "2026-06-10T00:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn accepted_default_route_receipt_body_uses_route_request_id() {
    let Some(db) = TestDb::maybe_new("default_route_receipt").await else {
        return;
    };
    let route = accepted_route();

    let rows = persist_default_route(&db.pool, &route)
        .await
        .expect("persist accepted default route");
    assert_eq!(rows, 1);

    let receipt_body: Value = sqlx::query_scalar(
        "SELECT receipt_body FROM dagdb_receipts \
         WHERE tenant_id = $1 AND namespace = $2 AND event_type = 'dagdb_record_accepted'",
    )
    .bind(&route.tenant_id)
    .bind(&route.memory_namespace)
    .fetch_one(&db.pool)
    .await
    .expect("load accepted default route receipt body");

    assert_eq!(
        receipt_body.get("request_id").and_then(Value::as_str),
        Some(route.request_id.as_str())
    );
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!(
                "skipping default route postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set"
            );
            return None;
        };
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut admin = PgConnection::connect(&database_url)
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut admin)
        .await
        .expect("drop existing default route test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create default route test schema");

        let separator = if database_url.contains('?') { '&' } else { '?' };
        let scoped_url =
            format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&scoped_url)
            .await
            .expect("connect default route test pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply base DAG DB schema");
        sqlx::raw_sql(DAGDB_OPERATIONAL_RECEIPT_EVENT_TYPES_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply operational receipt event type schema");
        sqlx::raw_sql(DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply PRD17B default route schema");
        Some(Self {
            pool,
            schema,
            database_url,
        })
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
                    .expect("connect for default route cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop default route test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}
