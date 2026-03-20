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

#[tokio::main]
async fn main() {
    // Initialise structured logging.
    tracing_subscriber::fmt::init();

    // Build config from environment, falling back to defaults.
    let bind_address = std::env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8443".into());

    let config = GatewayConfig {
        bind_address,
        ..GatewayConfig::default()
    };

    // Optionally connect to PostgreSQL and run migrations.
    let pool = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            tracing::info!("Connecting to PostgreSQL…");
            let pool = exo_gateway::db::init_pool(&url).await;
            tracing::info!("Database pool ready");
            Some(pool)
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
