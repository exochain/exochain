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

//! GAP-012 T4 — end-to-end proof that the gateway startup path provisions the
//! DAG DB schema.
//!
//! A FRESH database brought up *only* by the gateway's canonical
//! [`exo_gateway::db::init_pool`] startup runner must carry the DAG DB tables
//! (so the deployed gateway no longer 500s on the first DAG DB call) AND the
//! gateway's own tables, with SEPARATE `_sqlx_migrations` ledgers, so the two
//! crates' migrators do not collide despite reusing the same integer migration
//! versions (`20260505000001`, `20260602000001`).
//!
//! Requires `production-db` and a live Postgres in `EXO_DAGDB_TEST_DATABASE_URL`.

#![cfg(feature = "production-db")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sqlx::{Connection, PgConnection, Row};

/// Versions reused by BOTH the gateway and dag-db migrators.
const CROSS_CRATE_COLLISION_VERSIONS: [i64; 2] = [20260505000001, 20260602000001];

/// Parse `postgres://user:pass@host:port/dbname?...` and swap the database name,
/// preserving everything else, so we can target a throwaway database.
fn with_database_name(base_url: &str, db_name: &str) -> String {
    let (scheme_authority, after) = base_url
        .split_once("://")
        .map(|(scheme, rest)| (scheme.to_owned(), rest.to_owned()))
        .expect("database url has a scheme");
    // Split authority (user:pass@host:port) from the path+query.
    let (authority, path_query) = match after.split_once('/') {
        Some((authority, rest)) => (authority.to_owned(), rest.to_owned()),
        None => (after, String::new()),
    };
    let query = path_query
        .split_once('?')
        .map(|(_, q)| format!("?{q}"))
        .unwrap_or_default();
    format!("{scheme_authority}://{authority}/{db_name}{query}")
}

#[tokio::test]
async fn gateway_startup_provisions_dagdb_and_gateway_schemas_without_collision() {
    let Ok(base_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
        eprintln!(
            "skipping gateway schema provisioning integration test: \
             EXO_DAGDB_TEST_DATABASE_URL is not set"
        );
        return;
    };

    // A throwaway, test-scoped database name (kept under the 63-char identifier
    // limit) so the canonical startup runner provisions a genuinely fresh DB.
    let throwaway = format!("dagdb_gw_provision_{}_test", std::process::id());
    let throwaway_url = with_database_name(&base_url, &throwaway);

    // Admin connection on the base database to create/drop the throwaway DB.
    let mut admin = PgConnection::connect(&base_url)
        .await
        .expect("connect to EXO_DAGDB_TEST_DATABASE_URL for admin");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {throwaway}"
    )))
    .execute(&mut admin)
    .await
    .expect("drop any stale throwaway database");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {throwaway}")))
        .execute(&mut admin)
        .await
        .expect("create throwaway database");

    // Exercise the REAL production startup path. This must succeed end-to-end.
    let init_result = exo_gateway::db::init_pool(&throwaway_url).await;
    let pool = match init_result {
        Ok(pool) => pool,
        Err(error) => {
            // Best-effort cleanup before failing.
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS {throwaway}"
            )))
            .execute(&mut admin)
            .await;
            panic!("gateway init_pool must provision a fresh database, got: {error}");
        }
    };

    // Idempotent: a SECOND startup against the same database must not collide on
    // either migrator's `_sqlx_migrations` ledger.
    exo_gateway::db::init_pool(&throwaway_url)
        .await
        .expect("second gateway startup must be idempotent (no migrator collision)")
        .close()
        .await;

    // Gateway tables live in `public` with the gateway ledger.
    let users_in_public: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'users')",
    )
    .fetch_one(&pool)
    .await
    .expect("query for gateway users table");
    assert!(
        users_in_public,
        "gateway tables must be provisioned in public"
    );

    // DAG DB tables live in the dedicated `dagdb` schema.
    let dagdb_table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = 'dagdb' AND table_name LIKE 'dagdb_%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count dag-db tables in dedicated schema");
    assert!(
        dagdb_table_count >= 30,
        "the dedicated dagdb schema must carry the full dag-db table set, found {dagdb_table_count}"
    );

    // Separate ledgers: the colliding versions exist in BOTH ledgers, under
    // different descriptions, with no cross-contamination.
    let public_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM public._sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read gateway ledger");
    let dagdb_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM dagdb._sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read dag-db ledger");
    for version in CROSS_CRATE_COLLISION_VERSIONS {
        assert!(
            public_versions.contains(&version),
            "gateway ledger must record version {version}"
        );
        assert!(
            dagdb_versions.contains(&version),
            "dag-db ledger must record version {version} independently"
        );
    }

    // The colliding version is described differently in each ledger, proving the
    // two migrators tracked distinct SQL under the same integer version without
    // collision.
    let gateway_desc: String =
        sqlx::query("SELECT description FROM public._sqlx_migrations WHERE version = $1")
            .bind(20260505000001_i64)
            .fetch_one(&pool)
            .await
            .expect("gateway description for shared version")
            .get("description");
    let dagdb_desc: String =
        sqlx::query("SELECT description FROM dagdb._sqlx_migrations WHERE version = $1")
            .bind(20260505000001_i64)
            .fetch_one(&pool)
            .await
            .expect("dag-db description for shared version")
            .get("description");
    assert_ne!(
        gateway_desc, dagdb_desc,
        "the shared version must map to different migrations in each ledger"
    );

    // A representative DAG DB query answers through the pool using a BARE table
    // name, proving the pool `search_path` resolves dag-db queries to the
    // dedicated schema (the exact path the runtime takes).
    let memory_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM dagdb_memory_objects")
        .fetch_one(&pool)
        .await
        .expect("bare-named dag-db query must resolve via search_path");
    assert_eq!(memory_rows, 0, "fresh dag-db schema starts empty");

    pool.close().await;

    // Cleanup: drop the throwaway database.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {throwaway}"
    )))
    .execute(&mut admin)
    .await
    .expect("drop throwaway database");
    admin.close().await.ok();
}
