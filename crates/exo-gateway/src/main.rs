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

//! EXOCHAIN Gateway server binary.
//!
//! Reads configuration from the environment and starts the axum HTTP server.
//!
//! ## Environment variables
//!
//! | Variable        | Default           | Description                              |
//! |-----------------|-------------------|------------------------------------------|
//! | `BIND_ADDRESS`  | `127.0.0.1:8443`  | TCP address to bind                      |
//! | `DATABASE_URL`  | *(none)*          | PostgreSQL connection string             |
//!
//! If `DATABASE_URL` is unset the server starts without a database pool.
//! The `/ready` probe will return 503 until a pool is configured.

use exo_gateway::server::{GatewayConfig, serve};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .init();
}

#[tokio::main]
async fn main() {
    // Initialise structured logging.
    init_tracing();

    // Build config from environment, falling back to defaults.
    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8443".into());

    let config = GatewayConfig {
        bind_address,
        ..GatewayConfig::default()
    };

    // Optionally connect to PostgreSQL and run migrations.
    let pool = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            tracing::info!("Connecting to PostgreSQL…");
            match exo_gateway::db::init_pool(&url).await {
                Ok(pool) => {
                    tracing::info!("Database pool ready");
                    Some(pool)
                }
                Err(error) => {
                    tracing::error!("Database initialization failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Err(_) => {
            tracing::warn!(
                "DATABASE_URL not set — starting without database pool. \
                 /ready will return 503 until a pool is configured."
            );
            None
        }
    };

    tracing::info!("Starting exo-gateway on {}", config.bind_address);

    if let Err(e) = serve(config, pool).await {
        tracing::error!("Gateway terminated with error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("main.rs");

    fn init_tracing_source() -> &'static str {
        match SOURCE
            .split("fn init_tracing()")
            .nth(1)
            .and_then(|section| section.split("#[tokio::main]").next())
        {
            Some(source) => source,
            None => panic!("init_tracing must appear before main"),
        }
    }

    #[test]
    fn gateway_tracing_uses_env_filter_and_json_output() {
        let production = match SOURCE.split("#[cfg(test)]").next() {
            Some(source) => source,
            None => panic!("production source precedes tests"),
        };
        let init_tracing = init_tracing_source();
        let bare_fmt_init = concat!("tracing_subscriber::fmt", "::init()");

        assert!(
            !production.contains(bare_fmt_init),
            "gateway runtime must not use bare tracing_subscriber::fmt::init()"
        );
        assert!(
            init_tracing.contains("EnvFilter::try_from_default_env"),
            "gateway runtime logging must honor RUST_LOG via EnvFilter"
        );
        assert!(
            init_tracing.contains(".with_env_filter("),
            "gateway runtime logging must attach the EnvFilter to the subscriber"
        );
        assert!(
            init_tracing.contains(".json()"),
            "gateway runtime logging must emit structured JSON"
        );
    }
}
