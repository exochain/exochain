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

//! EXOCHAIN distributed node binary.
//!
//! Single binary for joining and participating in the constitutional
//! governance network. Every node runs the same verified code with
//! identical CGR kernel enforcement.
//!
//! ## Usage
//!
//! ```bash
//! exochain start                           # start a standalone node
//! exochain start --validator               # start as a BFT validator
//! exochain join --seed=seed1.exochain.io   # join an existing network
//! exochain status                          # show node status
//! exochain peers                           # list connected peers
//! ```

#![allow(clippy::type_complexity)]
#![cfg_attr(
    test,
    allow(clippy::expect_used, clippy::single_match, clippy::unwrap_used)
)]

mod api;
mod auth;
mod avc;
mod avc_rfc3161;
mod challenges;
mod cli;
mod config;
mod dashboard;
mod economy;
mod exoforge;
mod holons;
mod identity;
mod livesafe_public_output_ceremony_cli;
mod mcp;
mod metrics;
mod network;
mod passport;
mod provenance;
mod reactor;
mod receipt_dashboard;
mod root_genesis;
mod root_genesis_cli;
mod sentinels;
mod store;
mod sync;
mod telegram;
mod wire;
mod zerodentity;

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use clap::Parser;
use cli::{Cli, Command};
use exo_core::types::{Did, PublicKey};
#[cfg(feature = "unaudited-infrastructure-holons")]
use holons::{HolonEvent, HolonManagerConfig};
use libp2p_core::Multiaddr;
use network::{NetworkConfig, NetworkEvent, NetworkHandle};
use reactor::{ReactorConfig, ReactorEvent};
use sync::{SyncConfig, SyncEngine, SyncEvent};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "dagdb-gateway-proxy")]
const EXO_DAGDB_GATEWAY_URL_ENV: &str = "EXO_DAGDB_GATEWAY_URL";
#[cfg(feature = "dagdb-gateway-proxy")]
const EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV: &str = "EXO_DAGDB_GATEWAY_BEARER_TOKEN";
#[cfg(feature = "dagdb-gateway-proxy")]
const EXO_DAGDB_TENANT_ID_ENV: &str = "EXO_DAGDB_TENANT_ID";
#[cfg(feature = "dagdb-gateway-proxy")]
const EXO_DAGDB_NAMESPACE_ENV: &str = "EXO_DAGDB_NAMESPACE";
#[cfg(feature = "dagdb-gateway-proxy")]
const EXO_DAGDB_MCP_ENV_VARS: &[&str] = &[
    EXO_DAGDB_GATEWAY_URL_ENV,
    EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV,
    EXO_DAGDB_TENANT_ID_ENV,
    EXO_DAGDB_NAMESPACE_ENV,
];
const EXO_DAGDB_NODE_TENANT_ID_ENV: &str = "EXO_DAGDB_TENANT_ID";
const EXO_DAGDB_NODE_NAMESPACE_ENV: &str = "EXO_DAGDB_NAMESPACE";
const EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER_ENV: &str =
    "EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER";

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
    init_tracing();

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

/// Parse a list of validator DID strings, falling back to just this node's DID.
fn parse_validator_set(
    cli_validators: &Option<Vec<String>>,
    node_did: &Did,
) -> anyhow::Result<BTreeSet<Did>> {
    if let Some(vals) = cli_validators {
        if vals.is_empty() {
            anyhow::bail!("validator set must not be empty when --validators is supplied");
        }
        let mut parsed = BTreeSet::new();
        for raw in vals {
            let did =
                Did::new(raw).map_err(|e| anyhow::anyhow!("invalid validator DID '{raw}': {e}"))?;
            if !parsed.insert(did.clone()) {
                anyhow::bail!("duplicate validator DID '{did}' in --validators");
            }
        }
        Ok(parsed)
    } else {
        // Default: this node is the sole validator (standalone mode).
        let mut set = BTreeSet::new();
        set.insert(node_did.clone());
        Ok(set)
    }
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn mcp_node_context_from_env() -> anyhow::Result<mcp::NodeContext> {
    mcp_node_context_from_env_reader(|name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} is not valid Unicode")
        }
    })
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn mcp_node_context_from_env_reader<F>(read: F) -> anyhow::Result<mcp::NodeContext>
where
    F: Fn(&'static str) -> anyhow::Result<Option<String>>,
{
    let gateway_url = read(EXO_DAGDB_GATEWAY_URL_ENV)?;
    let bearer_token = read(EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV)?;
    let tenant_id = read(EXO_DAGDB_TENANT_ID_ENV)?;
    let namespace = read(EXO_DAGDB_NAMESPACE_ENV)?;

    let configured = [
        (EXO_DAGDB_GATEWAY_URL_ENV, gateway_url.as_ref()),
        (EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV, bearer_token.as_ref()),
        (EXO_DAGDB_TENANT_ID_ENV, tenant_id.as_ref()),
        (EXO_DAGDB_NAMESPACE_ENV, namespace.as_ref()),
    ];

    if configured.iter().all(|(_, value)| value.is_none()) {
        return Ok(mcp::NodeContext::empty());
    }

    let missing: Vec<&str> = configured
        .iter()
        .filter_map(|(name, value)| value.is_none().then_some(*name))
        .collect();
    let empty: Vec<&str> = configured
        .iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
                .then_some(*name)
        })
        .collect();

    if !missing.is_empty() || !empty.is_empty() {
        let mut details = Vec::new();
        if !missing.is_empty() {
            details.push(format!("missing {}", missing.join(", ")));
        }
        if !empty.is_empty() {
            details.push(format!("empty {}", empty.join(", ")));
        }
        anyhow::bail!(
            "DAG DB MCP gateway proxy config is incomplete: {}; set all of {} or unset all four to disable the proxy",
            details.join("; "),
            EXO_DAGDB_MCP_ENV_VARS.join(", ")
        );
    }

    tracing::info!(
        "DAG DB MCP gateway proxy configured from environment; gateway URL and bearer token omitted from logs"
    );

    Ok(mcp::NodeContext {
        dagdb_gateway: Some(mcp::context::DagDbGatewayConfig::new(
            gateway_url.unwrap_or_default(),
            bearer_token.unwrap_or_default(),
            tenant_id.unwrap_or_default(),
            namespace.unwrap_or_default(),
        )),
        ..mcp::NodeContext::empty()
    })
}

fn parse_seed_addrs(seed: &[String]) -> anyhow::Result<Vec<Multiaddr>> {
    if seed.is_empty() {
        anyhow::bail!("at least one seed address is required for join");
    }

    let mut parsed = Vec::with_capacity(seed.len());
    for raw in seed {
        if raw.starts_with('/') {
            let addr = raw.parse::<Multiaddr>().map_err(|e| {
                anyhow::anyhow!("invalid seed address '{raw}': malformed multiaddr: {e}")
            })?;
            parsed.push(addr);
            continue;
        }

        let (host, port) = raw.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("invalid seed address '{raw}': expected host:port or /multiaddr")
        })?;
        if host.is_empty() || port.is_empty() || port.contains(':') {
            anyhow::bail!("invalid seed address '{raw}': expected host:port or /multiaddr");
        }
        let port_number = port
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid seed address '{raw}': invalid TCP port: {e}"))?;
        let multiaddr = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => format!("/ip4/{host}/tcp/{port_number}"),
            Ok(IpAddr::V6(_)) => format!("/ip6/{host}/tcp/{port_number}"),
            Err(_) => format!("/dns4/{host}/tcp/{port_number}"),
        };
        let addr = multiaddr.parse::<Multiaddr>().map_err(|e| {
            anyhow::anyhow!("invalid seed address '{raw}': could not build multiaddr: {e}")
        })?;
        parsed.push(addr);
    }

    Ok(parsed)
}

fn derive_quic_port(p2p_port: u16) -> anyhow::Result<u16> {
    p2p_port.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("p2p port {p2p_port} cannot reserve adjacent QUIC port without overflow")
    })
}

fn parse_public_key_hex(value: &str) -> anyhow::Result<PublicKey> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        anyhow::bail!("validator public key must be 32 bytes, got {}", bytes.len());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(public_key))
}

fn parse_validator_public_key_entry(entry: &str) -> anyhow::Result<(Did, PublicKey)> {
    let (did_str, public_key_hex) = entry.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("validator public key must be did:exo:...=<64 hex bytes>")
    })?;
    let did = Did::new(did_str)?;
    let public_key = parse_public_key_hex(public_key_hex)?;
    let derived_did = identity::did_from_public_key(&public_key)?;
    if derived_did != did {
        anyhow::bail!("validator public key does not derive DID {did}; derived {derived_did}");
    }
    Ok((did, public_key))
}

fn resolve_validator_public_keys(
    entries: &Option<Vec<String>>,
    node_identity: &identity::NodeIdentity,
    validators: &BTreeSet<Did>,
) -> anyhow::Result<BTreeMap<Did, PublicKey>> {
    let mut keys = BTreeMap::new();
    keys.insert(node_identity.did.clone(), node_identity.public_key);

    if let Some(entries) = entries {
        for entry in entries {
            let (did, public_key) = parse_validator_public_key_entry(entry)?;
            if let Some(previous) = keys.insert(did.clone(), public_key) {
                if previous != public_key {
                    anyhow::bail!("conflicting public keys supplied for validator {did}");
                }
            }
        }
    }

    let missing: Vec<String> = validators
        .iter()
        .filter(|did| !keys.contains_key(*did))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "missing public keys for validators: {}. Pass --validator-public-key did:exo:...=<64 hex bytes> for every non-local validator.",
            missing.join(", ")
        );
    }

    Ok(keys)
}

/// Spawn the event fan-out task that dispatches network events to both
/// the consensus reactor and the sync engine.
struct BackgroundTasks {
    tasks: tokio::task::JoinSet<anyhow::Result<()>>,
}

impl BackgroundTasks {
    fn new() -> Self {
        Self {
            tasks: tokio::task::JoinSet::new(),
        }
    }

    fn spawn_critical<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(async move {
            future.await;
            Err(anyhow::anyhow!(
                "background task `{name}` exited unexpectedly"
            ))
        });
    }

    fn spawn_one_shot<F>(&mut self, _name: &'static str, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(async move {
            future.await;
            Ok(())
        });
    }

    async fn next_failure(&mut self) -> anyhow::Result<()> {
        loop {
            match self.tasks.join_next().await {
                Some(Ok(Ok(()))) => continue,
                Some(Ok(Err(error))) => return Err(error),
                Some(Err(error)) if error.is_panic() => {
                    return Err(anyhow::anyhow!("background task panicked: {error}"));
                }
                Some(Err(error)) => {
                    return Err(anyhow::anyhow!("background task failed: {error}"));
                }
                None => return std::future::pending().await,
            }
        }
    }

    async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }
}

fn count_metric_value(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

fn spawn_event_fanout(
    tasks: &mut BackgroundTasks,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    reactor_tx: mpsc::Sender<NetworkEvent>,
    sync_tx: mpsc::Sender<NetworkEvent>,
    metrics: metrics::SharedMetrics,
) {
    tasks.spawn_critical("network event fan-out", async move {
        while let Some(event) = event_rx.recv().await {
            // Log peer lifecycle events and update metrics.
            match &event {
                NetworkEvent::MessageReceived { source, topic, .. } => {
                    tracing::trace!(
                        peer = %source,
                        %topic,
                        "Wire message received"
                    );
                }
                NetworkEvent::PeerDiscovered { peer_id } => {
                    tracing::debug!(%peer_id, "Peer discovered");
                    metrics
                        .peer_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                NetworkEvent::PeerLost { peer_id } => {
                    tracing::debug!(%peer_id, "Peer lost");
                    // Saturating subtract via fetch_update.
                    let _ = metrics.peer_count.fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |v| Some(v.saturating_sub(1)),
                    );
                }
            }

            // Dispatch to reactor (consensus + governance messages).
            if reactor_tx.send(event.clone()).await.is_err() {
                tracing::warn!("Reactor event receiver dropped");
            }
            // Dispatch to sync engine (state sync messages).
            if sync_tx.send(event).await.is_err() {
                tracing::warn!("Sync event receiver dropped");
            }
        }
    });
}

fn avc_require_postgres_durability_from_env() -> anyhow::Result<bool> {
    let value = match std::env::var(avc::AVC_REQUIRE_POSTGRES_DURABILITY_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!(
                "{} is not valid Unicode",
                avc::AVC_REQUIRE_POSTGRES_DURABILITY_ENV
            );
        }
    };
    let value = value.trim();
    if value == "1" || value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        anyhow::bail!(
            "{} must be true, false, 1, or 0",
            avc::AVC_REQUIRE_POSTGRES_DURABILITY_ENV
        );
    }
}

fn required_env_value(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => anyhow::bail!("{name} must not be empty"),
        Err(std::env::VarError::NotPresent) => anyhow::bail!("{name} is required"),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid Unicode"),
    }
}

fn optional_scoped_bearer_from_env(
    name: &str,
) -> anyhow::Result<Option<zeroize::Zeroizing<String>>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(zeroize::Zeroizing::new(value))),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid Unicode"),
    }
}

fn livesafe_public_output_scoped_bearer_from_config(
    admin_token: &str,
    scoped_token: Option<zeroize::Zeroizing<String>>,
) -> anyhow::Result<auth::ScopedBearerAuth> {
    match scoped_token {
        Some(token) => {
            if token.as_str() == admin_token {
                anyhow::bail!(
                    "{} must be distinct from EXOCHAIN_ADMIN_BEARER_TOKEN",
                    EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER_ENV
                );
            }
            Ok(auth::ScopedBearerAuth::livesafe_public_adapter_output_authorization(token))
        }
        None => Ok(auth::ScopedBearerAuth::none()),
    }
}

fn dagdb_node_scope_from_env() -> anyhow::Result<(String, String)> {
    Ok((
        required_env_value(EXO_DAGDB_NODE_TENANT_ID_ENV)?,
        required_env_value(EXO_DAGDB_NODE_NAMESPACE_ENV)?,
    ))
}

async fn gateway_pool_from_env() -> anyhow::Result<sqlx::PgPool> {
    let database_url = required_env_value("DATABASE_URL")?;
    tracing::info!("DATABASE_URL configured - initializing gateway and DAG DB readiness pool");
    exo_gateway::db::init_pool(&database_url)
        .await
        .map_err(|error| anyhow::anyhow!("gateway database initialization failed: {error}"))
}

/// Start all subsystems for a running node.
#[allow(clippy::too_many_arguments)]
// 10 args is the minimum for a node bootstrap entry point:
// data_dir, api_host, api_port, p2p_port, round_timeout_ms, validator, validators,
// validator_public_keys, seed_addrs, is_join. Each is a distinct bootstrap
// parameter that came in through CLI parsing; bundling them behind a struct would
// add a layer of boilerplate with no safety benefit since this is the single call
// site from `main()`.
async fn start_node(
    data_dir: &std::path::Path,
    api_host: &str,
    api_port: u16,
    p2p_port: u16,
    round_timeout_ms: u64,
    validator: bool,
    validators: &Option<Vec<String>>,
    validator_public_key_entries: &Option<Vec<String>>,
    seed_addrs: Vec<Multiaddr>,
    is_join: bool,
) -> anyhow::Result<()> {
    // Bootstrap node identity.
    let node_identity = identity::load_or_create(data_dir)?;
    tracing::info!(
        did = %node_identity.did,
        pubkey = hex::encode(node_identity.public_key_bytes()),
        "Node identity ready"
    );

    let avc_require_postgres_durability = avc_require_postgres_durability_from_env()?;
    let gateway_pool = gateway_pool_from_env().await?;
    let (dagdb_tenant_id, dagdb_namespace) = dagdb_node_scope_from_env()?;

    // Open DAG DB-backed node store.
    let dag_store = store::DagDbNodeStore::open(
        gateway_pool.clone(),
        dagdb_tenant_id.clone(),
        dagdb_namespace.clone(),
    )
    .await?;
    let height = dag_store.committed_height_value()?;
    tracing::info!(height, "DAG store opened");

    // Open the DAG DB-backed 0dentity store.
    let mut zerodentity_store = zerodentity::store::ZerodentityStore::open_dagdb(
        gateway_pool.clone(),
        dagdb_tenant_id.clone(),
        dagdb_namespace.clone(),
    )
    .await?;
    let zd_receipt_signer: zerodentity::store::ReceiptSigner = {
        let identity = identity::load_or_create(data_dir)?;
        Arc::new(move |payload: &[u8]| identity.sign(payload))
    };
    zerodentity_store.set_receipt_signer(node_identity.did.clone(), zd_receipt_signer);
    if !zerodentity::store::ZerodentityStore::persistence_ready() {
        tracing::warn!(
            persistence_ready = zerodentity::store::ZerodentityStore::persistence_ready(),
            warning = zerodentity::store::ZerodentityStore::persistence_warning(),
            "0dentity store persistence is not ready"
        );
    }
    let zerodentity_store = std::sync::Arc::new(Mutex::new(zerodentity_store));
    tracing::info!(
        persistence_ready = zerodentity::store::ZerodentityStore::persistence_ready(),
        "0dentity store ready"
    );

    tracing::info!(
        api_port,
        p2p_port,
        round_timeout_ms,
        validator,
        did = %node_identity.did,
        "Starting exochain node"
    );

    // Start P2P networking.
    let net_config = NetworkConfig {
        tcp_port: p2p_port,
        quic_port: derive_quic_port(p2p_port)?,
        seed_addrs: seed_addrs.clone(),
    };

    let mut swarm = network::build_swarm()?;
    network::start_listening(&mut swarm, &net_config)?;

    // Dial seed nodes if joining.
    if is_join && !net_config.seed_addrs.is_empty() {
        let dialed = network::dial_seeds(&mut swarm, &net_config.seed_addrs)?;
        tracing::info!(dialed, "Dialed seed nodes");
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(256);
    let net_handle = NetworkHandle::new(cmd_tx);
    let mut background_tasks = BackgroundTasks::new();

    // Spawn the P2P network event loop.
    background_tasks.spawn_critical(
        "P2P network loop",
        network::run_network_loop(swarm, cmd_rx, event_tx),
    );
    tracing::info!(p2p_port, "P2P network started");

    // Create shared state.
    let shared_store = Arc::new(Mutex::new(dag_store));

    // Create metrics registry.
    let node_metrics = metrics::create_metrics();

    // --- Consensus reactor ---
    let validator_set = parse_validator_set(validators, &node_identity.did)?;
    let validator_public_keys = resolve_validator_public_keys(
        validator_public_key_entries,
        &node_identity,
        &validator_set,
    )?;
    let sync_validator_public_keys = validator_public_keys.clone();
    let reactor_config = ReactorConfig {
        node_did: node_identity.did.clone(),
        is_validator: validator,
        validators: validator_set.clone(),
        validator_public_keys,
        round_timeout_ms,
    };

    let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> = {
        let identity = identity::load_or_create(data_dir)?;
        Arc::new(move |data: &[u8]| identity.sign(data))
    };

    let reactor_state =
        reactor::create_reactor_state(&reactor_config, Arc::clone(&sign_fn), Some(&shared_store));
    let (reactor_tx, mut reactor_rx) = mpsc::channel::<ReactorEvent>(256);
    let (reactor_event_tx, reactor_event_rx) = mpsc::channel::<NetworkEvent>(256);

    background_tasks.spawn_critical(
        "consensus reactor",
        reactor::run_reactor(
            reactor_state.clone(),
            Arc::clone(&shared_store),
            net_handle.clone(),
            reactor_event_rx,
            reactor_tx,
        ),
    );

    // Set initial metrics from configuration.
    node_metrics
        .is_validator
        .store(u64::from(validator), std::sync::atomic::Ordering::Relaxed);
    node_metrics.validator_count.store(
        count_metric_value(validator_set.len()),
        std::sync::atomic::Ordering::Relaxed,
    );

    if validator {
        tracing::info!(
            validators = validator_set.len(),
            "Consensus reactor started (validator mode)"
        );
    } else {
        tracing::info!("Consensus reactor started (observer mode)");
    }

    // --- Sync engine ---
    let sync_config = SyncConfig {
        node_did: node_identity.did.clone(),
        validator_public_keys: sync_validator_public_keys.clone(),
        chunk_size: 100,
        max_sync_nodes: 200,
    };

    let (sync_event_tx, mut sync_event_rx) = mpsc::channel::<SyncEvent>(256);
    let (sync_net_event_tx, sync_net_event_rx) = mpsc::channel::<NetworkEvent>(256);

    let sync_engine = SyncEngine::new(
        sync_config,
        Arc::clone(&shared_store),
        net_handle.clone(),
        sync_event_tx,
    );

    // If joining, request initial state sync after a short delay for connections.
    if is_join {
        let mut sync_for_join = SyncEngine::new(
            SyncConfig {
                node_did: node_identity.did.clone(),
                validator_public_keys: sync_validator_public_keys.clone(),
                chunk_size: 100,
                max_sync_nodes: 200,
            },
            Arc::clone(&shared_store),
            net_handle.clone(),
            mpsc::channel::<SyncEvent>(1).0,
        );
        background_tasks.spawn_one_shot("initial state sync", async move {
            // Wait briefly for connections to establish.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Err(e) = sync_for_join.request_sync().await {
                tracing::warn!(err = %e, "Failed to initiate state sync");
            }
        });
    }

    // Spawn the sync engine event loop.
    background_tasks.spawn_critical(
        "sync engine",
        sync::run_sync_engine(sync_engine, sync_net_event_rx),
    );
    tracing::info!("Sync engine started");

    // --- Event fan-out ---
    spawn_event_fanout(
        &mut background_tasks,
        event_rx,
        reactor_event_tx,
        sync_net_event_tx,
        Arc::clone(&node_metrics),
    );

    // --- Event loggers (with metrics updates) ---
    let reactor_metrics = Arc::clone(&node_metrics);
    background_tasks.spawn_critical("reactor event logger", async move {
        while let Some(event) = reactor_rx.recv().await {
            match event {
                ReactorEvent::NodeCommitted {
                    hash,
                    height,
                    round,
                } => {
                    reactor_metrics
                        .committed_height
                        .store(height, std::sync::atomic::Ordering::Relaxed);
                    reactor_metrics
                        .consensus_round
                        .store(round, std::sync::atomic::Ordering::Relaxed);
                    reactor_metrics
                        .dag_nodes_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(%hash, height, round, "Committed");
                }
                ReactorEvent::RoundAdvanced { round } => {
                    reactor_metrics
                        .consensus_round
                        .store(round, std::sync::atomic::Ordering::Relaxed);
                    tracing::trace!(round, "Round advanced");
                }
                ReactorEvent::GovernanceEventReceived { event } => {
                    tracing::info!(
                        sender = %event.sender,
                        event_type = ?event.event_type,
                        "Governance event received"
                    );
                }
            }
        }
    });

    let sync_metrics = Arc::clone(&node_metrics);
    background_tasks.spawn_critical("sync event logger", async move {
        while let Some(event) = sync_event_rx.recv().await {
            match event {
                SyncEvent::Progress {
                    from_height,
                    to_height,
                    total_nodes,
                } => {
                    sync_metrics
                        .sync_in_progress
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(from_height, to_height, total_nodes, "Sync progress");
                }
                SyncEvent::Complete { committed_height } => {
                    sync_metrics
                        .sync_in_progress
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    sync_metrics
                        .committed_height
                        .store(committed_height, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(committed_height, "Sync complete — node is caught up");
                }
                SyncEvent::ServedSnapshot {
                    peer,
                    from_height,
                    nodes_sent,
                } => {
                    tracing::debug!(
                        %peer, from_height, nodes_sent,
                        "Served snapshot to peer"
                    );
                }
            }
        }
    });

    // --- Infrastructure Holons ---
    #[cfg(feature = "unaudited-infrastructure-holons")]
    {
        let holon_identity = identity::load_or_create(data_dir)?;
        let holon_authority_did = holon_identity.did.clone();
        let holon_authority_public_key = *holon_identity.public_key();
        let holon_authority_signer = Arc::new(move |message: &[u8]| holon_identity.sign(message));
        let holon_config = HolonManagerConfig {
            node_did: node_identity.did.clone(),
            root_did: holon_authority_did,
            root_public_key: holon_authority_public_key,
            root_signer: holon_authority_signer,
            // No external attestation is wired yet: `root_did`/`root_public_key`/
            // `root_signer` above are all derived from the same freshly-loaded
            // node identity, i.e. a self-issued root authority with no
            // witnessed ceremony or lineage distinct from the signer. Per
            // ratified decision D5, the kernel must reject this until a real
            // external attestation source (a distinct witnessing party) is
            // wired in — tracked in `Initiatives/fix-onyx-4-r5-holons-stub-context.md`.
            root_attestation: None,
            provenance_timestamp_source: holons::hlc_provenance_timestamp_source(),
            topology_interval_secs: 60,
            scaling_interval_secs: 300,
            health_interval_secs: 30,
        };

        let (holon_event_tx, mut holon_event_rx) = mpsc::channel::<HolonEvent>(256);

        background_tasks.spawn_critical(
            "infrastructure holon manager",
            holons::run_holon_manager(
                holon_config,
                Arc::clone(&reactor_state),
                Arc::clone(&shared_store),
                net_handle.clone(),
                holon_event_tx,
            ),
        );
        tracing::warn!(
            enabled = holons::infrastructure_holons_enabled(),
            feature_flag = holons::INFRASTRUCTURE_HOLONS_FEATURE,
            initiative = holons::INFRASTRUCTURE_HOLONS_INITIATIVE,
            "Infrastructure Holons started under unaudited feature gate"
        );

        // Holon event logger (with metrics updates).
        let holon_metrics = Arc::clone(&node_metrics);
        background_tasks.spawn_critical("holon event logger", async move {
            while let Some(event) = holon_event_rx.recv().await {
                match event {
                    HolonEvent::TopologyAnalysis {
                        peer_count,
                        diversity_score_bp,
                        recommendation,
                    } => {
                        holon_metrics.peer_count.store(
                            count_metric_value(peer_count),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::info!(
                            peer_count,
                            diversity_score_bp,
                            %recommendation,
                            "Topology Holon"
                        );
                    }
                    HolonEvent::ScalingRecommendation {
                        validator_count,
                        node_count,
                        recommendation,
                    } => {
                        holon_metrics.validator_count.store(
                            count_metric_value(validator_count),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::info!(
                            validator_count,
                            node_count,
                            %recommendation,
                            "Scaling Holon"
                        );
                    }
                    HolonEvent::HealthCheck {
                        consensus_round,
                        committed_height,
                        status,
                    } => match &status {
                        holons::HealthStatus::Healthy => {
                            tracing::debug!(
                                consensus_round,
                                committed_height,
                                "Health Holon: healthy"
                            );
                        }
                        holons::HealthStatus::Degraded { reason } => {
                            tracing::warn!(
                                consensus_round,
                                committed_height,
                                %reason,
                                "Health Holon: degraded"
                            );
                        }
                        holons::HealthStatus::Critical { reason } => {
                            tracing::error!(
                                consensus_round,
                                committed_height,
                                %reason,
                                "Health Holon: CRITICAL"
                            );
                        }
                    },
                    HolonEvent::HolonTerminated { holon_id, reason } => {
                        tracing::error!(
                            %holon_id,
                            %reason,
                            "Infrastructure Holon terminated"
                        );
                    }
                }
            }
        });
    }

    #[cfg(not(feature = "unaudited-infrastructure-holons"))]
    tracing::warn!(
        enabled = holons::infrastructure_holons_enabled(),
        feature_flag = holons::INFRASTRUCTURE_HOLONS_FEATURE,
        initiative = holons::INFRASTRUCTURE_HOLONS_INITIATIVE,
        "Infrastructure Holons disabled pending product disposition"
    );

    // NOTE: /health and /ready are provided by the gateway (exo-gateway)
    // with uptime tracking and DB readiness checks. Node-specific probes
    // are available via /api/v1/governance/status and /api/v1/sentinels.

    // Build the metrics HTTP route.
    let metrics_handle = Arc::clone(&node_metrics);
    let metrics_router = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let m = Arc::clone(&metrics_handle);
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    m.render(),
                )
            }
        }),
    );

    // Build the governance API router.
    //
    // `crosschecked_trust` starts empty: no CrossChecked authority is
    // trusted until an operator explicitly delegates one via the root
    // authority (VCG-007, D3), which keeps `POST /api/v1/receipts`
    // fail-closed by default even when the
    // `unaudited-crosschecked-receipt-anchor` feature is compiled in.
    let api_state = Arc::new(api::NodeApiState {
        reactor_state: Arc::clone(&reactor_state),
        store: Arc::clone(&shared_store),
        net_handle: net_handle.clone(),
        node_did: node_identity.did.clone(),
        sign_fn: Arc::clone(&sign_fn),
        crosschecked_trust: Arc::new(std::sync::Mutex::new(api::CrossCheckedTrustAnchor::empty(
            node_identity.did.clone(),
        ))),
    });
    let governance_router = api::governance_router(api_state);

    // Generate admin token for privileged API authentication.
    //
    // Security note: we do not log any token material. A log aggregator that
    // captures node stdout must not receive even a prefix of the
    // governance-write credential. The full token is written only to a file
    // with restrictive permissions (owner read/write only, 0600) under the
    // node's data directory.
    let admin_token = match std::env::var("EXOCHAIN_ADMIN_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(token) => zeroize::Zeroizing::new(token),
        None => auth::generate_admin_token().map_err(|e| {
            tracing::error!(err = %e, "Failed to generate admin token — aborting startup");
            anyhow::anyhow!("admin token entropy failed: {e}")
        })?,
    };
    let token_path = data_dir.join("admin_token");
    if let Err(e) = auth::write_admin_token_file(&token_path, admin_token.as_str()) {
        tracing::error!(
            path = %token_path.display(),
            err = %e,
            "Failed to write admin token file — aborting startup"
        );
        return Err(anyhow::anyhow!("admin token persistence failed: {e}"));
    }
    tracing::info!(
        token_path = %token_path.display(),
        "Admin bearer token generated and written to restrictive file; token material omitted from logs"
    );
    let bearer_auth = auth::BearerAuth {
        token: Arc::new(admin_token),
    };
    let scoped_bearer_auth = livesafe_public_output_scoped_bearer_from_config(
        bearer_auth.token.as_str(),
        optional_scoped_bearer_from_env(
            EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER_ENV,
        )?,
    )?;
    if scoped_bearer_auth.livesafe_public_adapter_output_authorization_configured() {
        tracing::info!(
            env = EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER_ENV,
            route = auth::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE,
            "Scoped LiveSafe public adapter-output bearer configured; token material omitted from logs"
        );
    }

    // Build the agent passport API router.
    let passport_state = Arc::new(passport::PassportApiState {
        reactor_state: Arc::clone(&reactor_state),
        store: Arc::clone(&shared_store),
        zerodentity_store: Arc::clone(&zerodentity_store),
    });
    let passport_router = passport::passport_router(passport_state, bearer_auth.clone());

    // Build the dashboard router (serves GET /).
    let dashboard_router = dashboard::dashboard_router();

    // Build the challenge/dispute router.
    let challenge_store = Arc::new(std::sync::Mutex::new(challenges::ChallengeStore::new()));
    let challenge_router = challenges::challenge_router(Arc::clone(&challenge_store));

    // Build the provenance API router.
    let provenance_state = Arc::new(provenance::ProvenanceState {
        store: Arc::clone(&shared_store),
    });
    let provenance_router = provenance::provenance_router(provenance_state);

    // Build the receipt drill-down dashboard.
    let receipt_dashboard_router = receipt_dashboard::receipt_dashboard_router();

    // Build the ExoForge build orchestration dashboard.
    let forge_state: exoforge::SharedForgeState = Arc::new(Mutex::new(
        exoforge::ForgeState::new_zerodentity()
            .map_err(|error| anyhow::anyhow!("ExoForge HLC initialization failed: {error}"))?,
    ));
    let forge_router = exoforge::exoforge_router(forge_state);
    tracing::info!("ExoForge initialized — 0dentity spec loaded, 56 tasks across 12 phases");

    // Build the sentinel API router and start the sentinel loop.
    let sentinel_state: sentinels::SharedSentinelState =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let sentinel_router = sentinels::sentinel_router(Arc::clone(&sentinel_state));
    let (alert_tx, alert_rx) = tokio::sync::mpsc::channel::<sentinels::SentinelAlert>(64);

    // Spawn sentinel background loop.
    background_tasks.spawn_critical(
        "sentinel loop",
        sentinels::run_sentinel_loop(
            Arc::clone(&reactor_state),
            Arc::clone(&shared_store),
            Arc::clone(&zerodentity_store),
            Arc::clone(&sentinel_state),
            alert_tx,
            std::time::Duration::from_secs(30),
        ),
    );

    // Start the Telegram adjutant if configured.
    if let Some(tg_config) = telegram::AdjutantConfig::from_env() {
        tracing::info!("Telegram adjutant configured — starting bot");
        match telegram::Adjutant::new(tg_config) {
            Ok(adjutant) => {
                background_tasks.spawn_critical(
                    "Telegram adjutant",
                    telegram::run_adjutant(
                        adjutant,
                        alert_rx,
                        Arc::clone(&reactor_state),
                        Arc::clone(&shared_store),
                        Arc::clone(&challenge_store),
                        Arc::clone(&sentinel_state),
                        Arc::clone(&zerodentity_store),
                    ),
                );
            }
            Err(e) => {
                tracing::warn!(err = %e, "Telegram adjutant disabled: HTTP client setup failed");
                drop(alert_rx);
            }
        }
    } else {
        tracing::info!(
            "Telegram adjutant not configured — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable"
        );
        // Drop the alert receiver so sentinels don't block.
        drop(alert_rx);
    }

    // Build the AVC API router (Autonomous Volition Credentials).
    let avc_state = Arc::new(
        avc::AvcApiState::with_durable_registry(
            data_dir,
            node_identity.did.clone(),
            Arc::clone(&sign_fn),
            Some(gateway_pool.clone()),
            Some(Arc::clone(&shared_store)),
            avc_require_postgres_durability,
        )
        .await?,
    );
    avc_state.register_validator_public_keys(sync_validator_public_keys.clone())?;
    {
        let issuer_registration_now = avc::trusted_local_hlc_timestamp(avc_state.as_ref())?;
        let issuer_registration_sign_fn = Arc::clone(&sign_fn);
        match avc::configure_issuer_registration_authority_from_env(
            avc_state.as_ref(),
            &node_identity.public_key,
            &issuer_registration_now,
            move |payload| issuer_registration_sign_fn(payload),
        )? {
            Some(operator_did) => {
                let chain_link_count = avc_state
                    .find_delegated_issuer_registration_chain(&operator_did)
                    .map(|chain| chain.depth())
                    .unwrap_or(0);
                tracing::info!(
                    operator_did = %operator_did,
                    chain_link_count,
                    "AVC runtime issuer-registration authority granted to configured operator"
                );
            }
            None => {
                tracing::warn!(
                    env = avc::AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV,
                    "AVC runtime issuer-registration operator not configured; \
                     POST /api/v1/avc/issuers will refuse every request until \
                     an authority grant exists"
                );
            }
        }
    }
    match avc::load_configured_root_trust_bundle(avc_state.as_ref())? {
        Some(registration) => {
            tracing::info!(
                ceremony_id = %registration.ceremony_id,
                bundle_id = %registration.bundle_id,
                issuer_did = %registration.issuer_did,
                "AVC root trust issuer registered from verified bundle"
            );
        }
        None => {
            tracing::warn!(
                env = avc::AVC_ROOT_TRUST_BUNDLE_ENV,
                "AVC root trust bundle not configured; issuer registry starts without root delegation"
            );
        }
    }
    // Restore durable per-issuer runtime registrations (VCG-006b / #736 hard
    // requirement (a)) now that every verified startup-config trust anchor
    // that could be a chain root has been registered above. Each stored
    // `exo-authority` DelegationRegistry chain is re-verified before its key
    // becomes resolvable again, so a restart can never resurrect an
    // unauthorized key. A record that fails re-verification is skipped and
    // logged at `warn` level rather than aborting startup (VCG-006b
    // availability corrective) — the `?` below only propagates genuine
    // registry-unavailable errors (e.g. a poisoned mutex), never a
    // per-record verification failure.
    {
        let restore_now = avc::trusted_local_hlc_timestamp(avc_state.as_ref())?;
        avc_state.restore_registered_issuer_keys(&restore_now)?;
    }
    let avc_router = avc::avc_router(Arc::clone(&avc_state));
    tracing::info!(
        "AVC router ready — /api/v1/avc/{{issue,validate,receipts,receipts/emit,protocol,delegate,revoke,:id}}, /api/v1/agents/:did/avcs"
    );

    // Build the economy API router (zero-priced launch settlement).
    let economy_settlement_signer: economy::SettlementSigner = {
        let identity = identity::load_or_create(data_dir)?;
        Arc::new(move |payload: &[u8]| identity.sign(payload))
    };
    let economy_state = Arc::new(economy::EconomyApiState::with_durable_store(
        economy_settlement_signer,
        Arc::clone(&shared_store),
    ));
    let economy_router = economy::economy_router(Arc::clone(&economy_state));
    tracing::info!(
        "Economy router ready — /api/v1/economy/* with durable HonorGood mission economics anchors (zero-priced launch policy active)"
    );

    // Build 0dentity routers.
    let zd_onboarding_state =
        zerodentity::onboarding::OnboardingState::new(std::sync::Arc::clone(&zerodentity_store));
    let zd_api_state = zerodentity::api::ApiState::new(std::sync::Arc::clone(&zerodentity_store));
    let zerodentity_onboarding_router =
        zerodentity::onboarding::onboarding_router(zd_onboarding_state);
    let zerodentity_api_router = zerodentity::api::zerodentity_api_router(zd_api_state);
    let zerodentity_dashboard_router = zerodentity::dashboard::zerodentity_dashboard_router();
    let zerodentity_onboarding_ui_router =
        zerodentity::onboarding_ui::zerodentity_onboarding_router();
    tracing::info!(
        "0dentity routers ready — /0dentity, /0dentity/dashboard/:did, /api/v1/0dentity/*"
    );

    // Merge metrics + governance + passport + dashboard into a single extra router
    // and apply bearer-token auth middleware. 0dentity signed writes use their
    // local DID session and request-signature verifiers.
    // NOTE: /health and /ready are provided by the gateway's own router.
    let extra_router = metrics_router
        .merge(governance_router)
        .merge(passport_router)
        .merge(dashboard_router)
        .merge(challenge_router)
        .merge(provenance_router)
        .merge(receipt_dashboard_router)
        .merge(sentinel_router)
        .merge(forge_router)
        .merge(avc_router)
        .merge(economy_router)
        .merge(zerodentity_onboarding_router)
        .merge(zerodentity_api_router)
        .merge(zerodentity_dashboard_router)
        .merge(zerodentity_onboarding_ui_router)
        .layer(axum::middleware::from_fn(move |req, next| {
            let a = bearer_auth.clone();
            let scoped = scoped_bearer_auth.clone();
            async move {
                if scoped.livesafe_public_adapter_output_authorization_configured() {
                    auth::require_bearer_on_writes_with_scoped_bearers(a, scoped, req, next).await
                } else {
                    auth::require_bearer_on_writes(a, req, next).await
                }
            }
        }));

    // Start the gateway HTTP server (blocks).
    //
    // Security note (GAP AMBER — Onyx pass 3): we bind to the caller-
    // supplied `api_host` which defaults to `127.0.0.1` (loopback only).
    // Opt-in to broader exposure (e.g. `0.0.0.0`) requires an explicit
    // `--api-host` flag. This protects the admin-bearer-token write
    // surface from accidental internet exposure when the operator
    // forgets to put a reverse proxy in front.
    let bind_address = format!("{api_host}:{api_port}");
    if api_host == "0.0.0.0" {
        tracing::warn!(
            %bind_address,
            "API bound to 0.0.0.0 — admin-write endpoints are reachable on all interfaces. \
             Ensure you have a TLS-terminating front door AND rotate the admin token regularly."
        );
    }
    let gateway_config = exo_gateway::server::GatewayConfig {
        bind_address: bind_address.clone(),
        ..exo_gateway::server::GatewayConfig::default()
    };
    if is_join {
        tracing::info!(
            %bind_address,
            "Node joined — dashboard at http://localhost:{api_port}"
        );
    } else {
        tracing::info!(
            %bind_address,
            "Dashboard at http://localhost:{api_port}"
        );
    }

    let serve_fut = exo_gateway::server::serve_with_extra_routes(
        gateway_config,
        Some(gateway_pool),
        Some(extra_router),
    );

    tracing::info!(
        %bind_address,
        "Node fully started — SIGTERM/Ctrl+C will trigger graceful shutdown"
    );
    let run_result = tokio::select! {
        server_result = serve_fut => server_result.map_err(anyhow::Error::from),
        task_result = background_tasks.next_failure() => task_result,
    };
    background_tasks.shutdown().await;
    run_result?;

    tracing::info!("HTTP server drained — signaling subsystems to stop");
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tracing::info!("Graceful shutdown complete");

    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Start {
            api_port,
            api_host,
            p2p_port,
            round_timeout_ms,
            data_dir,
            validator,
            validators,
            validator_public_keys,
        } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let cfg = config::load_or_create(&data_dir)?;

            // Resolution order: CLI flag > $PORT env (set by Railway/Heroku-style PaaS) > config.toml.
            let api_port = api_port
                .or_else(|| std::env::var("PORT").ok().and_then(|s| s.parse().ok()))
                .unwrap_or(cfg.api_port);
            let p2p_port = p2p_port.unwrap_or(cfg.p2p_port);

            start_node(
                &data_dir,
                &api_host,
                api_port,
                p2p_port,
                round_timeout_ms,
                validator,
                &validators,
                &validator_public_keys,
                vec![],
                false,
            )
            .await
        }

        Command::Join {
            seed,
            api_port,
            api_host,
            p2p_port,
            round_timeout_ms,
            data_dir,
            validator,
            validators,
            validator_public_keys,
        } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let cfg = config::load_or_create(&data_dir)?;

            // Resolution order: CLI flag > $PORT env (set by Railway/Heroku-style PaaS) > config.toml.
            let api_port = api_port
                .or_else(|| std::env::var("PORT").ok().and_then(|s| s.parse().ok()))
                .unwrap_or(cfg.api_port);
            let p2p_port = p2p_port.unwrap_or(cfg.p2p_port);

            let seed_addrs = parse_seed_addrs(&seed)?;

            start_node(
                &data_dir,
                &api_host,
                api_port,
                p2p_port,
                round_timeout_ms,
                validator,
                &validators,
                &validator_public_keys,
                seed_addrs,
                true,
            )
            .await
        }

        Command::Status { data_dir } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let node_identity = identity::load_or_create(&data_dir)?;
            let gateway_pool = gateway_pool_from_env().await?;
            let (dagdb_tenant_id, dagdb_namespace) = dagdb_node_scope_from_env()?;
            let dag_store =
                store::DagDbNodeStore::open(gateway_pool, dagdb_tenant_id, dagdb_namespace).await?;

            println!("Node:   {}", node_identity.did);
            println!("Height: {}", dag_store.committed_height_value()?);
            println!("Data:   {}", data_dir.display());

            Ok(())
        }

        Command::Peers { data_dir: _ } => {
            println!("Peer listing requires a running node. Use `exochain start` first.");
            Ok(())
        }

        Command::Mcp {
            data_dir,
            actor_did,
            sse,
        } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let node_identity = identity::load_or_create(&data_dir)?;

            let did = if let Some(ref did_str) = actor_did {
                Did::new(did_str).map_err(|e| anyhow::anyhow!("invalid actor DID: {e}"))?
            } else {
                node_identity.did.clone()
            };
            if did != node_identity.did {
                return Err(anyhow::anyhow!(
                    "MCP actor DID must match the local node identity DID for signed adjudication"
                ));
            }
            let node_identity_for_log = node_identity.did.clone();
            let mcp_authority_did = node_identity.did.clone();
            let mcp_authority_public_key = *node_identity.public_key();
            let mcp_authority_signer = Arc::new(move |message: &[u8]| node_identity.sign(message));

            // The standalone `exochain mcp` command does NOT connect to a
            // running node. In `dagdb-gateway-proxy` builds it may still carry
            // an operator-configured DAG DB gateway proxy context from env;
            // with no DAG DB env configured, tools continue to fail closed as
            // unconfigured.
            #[cfg(feature = "dagdb-gateway-proxy")]
            let server = mcp::McpServer::with_context_and_authority(
                did,
                mcp_node_context_from_env()?,
                mcp_authority_did,
                mcp_authority_public_key,
                mcp_authority_signer,
            );

            #[cfg(not(feature = "dagdb-gateway-proxy"))]
            let server = mcp::McpServer::with_authority(
                did,
                mcp_authority_did,
                mcp_authority_public_key,
                mcp_authority_signer,
            );

            if let Some(bind) = sse {
                eprintln!("[exochain-mcp] Starting MCP server on SSE at {bind}...");
                eprintln!("[exochain-mcp] Node identity: {}", node_identity_for_log);
                mcp::serve_sse(server, &bind)
                    .await
                    .map_err(|e| anyhow::anyhow!("MCP SSE server error: {e}"))
            } else {
                eprintln!("[exochain-mcp] Starting MCP server on stdio...");
                eprintln!("[exochain-mcp] Node identity: {}", node_identity_for_log);
                mcp::serve_stdio(server)
                    .await
                    .map_err(|e| anyhow::anyhow!("MCP stdio server error: {e}"))
            }
        }
        Command::Genesis { command } => root_genesis_cli::run_genesis_command(command).await,
        Command::Avc { command } => {
            livesafe_public_output_ceremony_cli::run_avc_command(command).await
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn local_node_did() -> Did {
        Did::new("did:exo:local").unwrap()
    }

    #[test]
    fn parse_validator_set_defaults_to_local_node_when_absent() {
        let node_did = local_node_did();
        let validators = parse_validator_set(&None, &node_did).unwrap();

        assert_eq!(validators.len(), 1);
        assert!(validators.contains(&node_did));
    }

    #[test]
    fn parse_validator_set_rejects_invalid_did() {
        let err = parse_validator_set(
            &Some(vec!["did:exo:valid".to_owned(), "not-a-did".to_owned()]),
            &local_node_did(),
        )
        .unwrap_err();

        let text = err.to_string();
        assert!(text.contains("invalid validator DID"));
        assert!(text.contains("not-a-did"));
    }

    #[test]
    fn parse_validator_set_rejects_duplicate_did() {
        let err = parse_validator_set(
            &Some(vec!["did:exo:alice".to_owned(), "did:exo:alice".to_owned()]),
            &local_node_did(),
        )
        .unwrap_err();

        let text = err.to_string();
        assert!(text.contains("duplicate validator DID"));
        assert!(text.contains("did:exo:alice"));
    }

    #[test]
    fn livesafe_public_output_scoped_bearer_config_rejects_admin_token_reuse_without_leaking_secret()
     {
        let err = match livesafe_public_output_scoped_bearer_from_config(
            "shared-bearer-token",
            Some(zeroize::Zeroizing::new("shared-bearer-token".to_owned())),
        ) {
            Ok(_) => panic!("scoped LiveSafe bearer must reject admin token reuse"),
            Err(err) => err,
        };

        let text = err.to_string();
        assert!(text.contains("EXOCHAIN_ADMIN_BEARER_TOKEN"));
        assert!(text.contains(EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER_ENV));
        assert!(!text.contains("shared-bearer-token"));
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn mcp_context_from_env_pairs(
        pairs: &[(&'static str, &str)],
    ) -> anyhow::Result<mcp::NodeContext> {
        let values: BTreeMap<&'static str, String> = pairs
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();
        mcp_node_context_from_env_reader(|name| Ok(values.get(name).cloned()))
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn mcp_dagdb_env_config_builds_gateway_context_when_complete() {
        let context = mcp_context_from_env_pairs(&[
            (EXO_DAGDB_GATEWAY_URL_ENV, "http://127.0.0.1:3000"),
            (
                EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV,
                "super-secret-token-value",
            ),
            (EXO_DAGDB_TENANT_ID_ENV, "tenant-a"),
            (EXO_DAGDB_NAMESPACE_ENV, "primary"),
        ])
        .unwrap();

        let config = context
            .dagdb_gateway
            .as_ref()
            .expect("complete env builds gateway config");
        assert_eq!(config.base_url.as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(
            config.bearer_token.as_ref().map(|token| token.as_str()),
            Some("super-secret-token-value")
        );
        assert_eq!(config.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(config.namespace.as_deref(), Some("primary"));
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn mcp_dagdb_env_config_absent_preserves_unconfigured_context() {
        let context = mcp_context_from_env_pairs(&[]).unwrap();

        assert!(context.dagdb_gateway.is_none());
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn mcp_dagdb_env_config_partial_or_empty_fails_without_leaking_token() {
        let err = match mcp_context_from_env_pairs(&[
            (EXO_DAGDB_GATEWAY_URL_ENV, "http://127.0.0.1:3000"),
            (
                EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV,
                "super-secret-token-value",
            ),
            (EXO_DAGDB_TENANT_ID_ENV, "tenant-a"),
        ]) {
            Ok(_) => panic!("partial DAG DB env config must fail"),
            Err(err) => err,
        };
        let text = err.to_string();
        assert!(text.contains("DAG DB MCP gateway proxy config is incomplete"));
        assert!(text.contains(EXO_DAGDB_NAMESPACE_ENV));
        assert!(!text.contains("super-secret-token-value"));

        let err = match mcp_context_from_env_pairs(&[
            (EXO_DAGDB_GATEWAY_URL_ENV, "http://127.0.0.1:3000"),
            (EXO_DAGDB_GATEWAY_BEARER_TOKEN_ENV, " "),
            (EXO_DAGDB_TENANT_ID_ENV, "tenant-a"),
            (EXO_DAGDB_NAMESPACE_ENV, "primary"),
        ]) {
            Ok(_) => panic!("empty DAG DB env config value must fail"),
            Err(err) => err,
        };
        let text = err.to_string();
        assert!(text.contains("empty EXO_DAGDB_GATEWAY_BEARER_TOKEN"));
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn mcp_command_uses_context_bound_server_when_dagdb_proxy_feature_is_enabled() {
        let source = include_str!("main.rs");
        let command_mcp_section = source
            .split("Command::Mcp")
            .nth(1)
            .and_then(|section| section.split("Command::Genesis").next())
            .expect("MCP command section present");

        assert!(command_mcp_section.contains("mcp_node_context_from_env()?"));
        assert!(command_mcp_section.contains("McpServer::with_context_and_authority"));
    }

    #[test]
    fn parse_seed_addrs_rejects_malformed_seed() {
        let err = parse_seed_addrs(&[
            "/ip4/127.0.0.1/tcp/4001".to_owned(),
            "seed-without-port".to_owned(),
        ])
        .unwrap_err();

        let text = err.to_string();
        assert!(text.contains("invalid seed address"));
        assert!(text.contains("seed-without-port"));
    }

    #[test]
    fn parse_seed_addrs_parses_multiaddr_ip_and_dns_host_port() {
        let addrs = parse_seed_addrs(&[
            "/ip4/127.0.0.1/tcp/4001".to_owned(),
            "192.0.2.10:4002".to_owned(),
            "seed1.exochain.io:4003".to_owned(),
        ])
        .unwrap();

        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].to_string(), "/ip4/127.0.0.1/tcp/4001");
        assert_eq!(addrs[1].to_string(), "/ip4/192.0.2.10/tcp/4002");
        assert_eq!(addrs[2].to_string(), "/dns4/seed1.exochain.io/tcp/4003");
    }

    #[test]
    fn node_tracing_uses_env_filter_and_json_output() {
        let source = include_str!("main.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let init_tracing = source
            .split("fn init_tracing()")
            .nth(1)
            .and_then(|section| section.split("#[tokio::main]").next())
            .expect("init_tracing must appear before main");
        let bare_fmt_init = concat!("tracing_subscriber::fmt", "::init()");

        assert!(
            !production.contains(bare_fmt_init),
            "node runtime must not use bare tracing_subscriber::fmt::init()"
        );
        assert!(
            init_tracing.contains("EnvFilter::try_from_default_env"),
            "node runtime logging must honor RUST_LOG via EnvFilter"
        );
        assert!(
            init_tracing.contains(".with_env_filter("),
            "node runtime logging must attach the EnvFilter to the subscriber"
        );
        assert!(
            init_tracing.contains(".json()"),
            "node runtime logging must emit structured JSON"
        );
    }

    #[test]
    fn cli_accepts_consensus_round_timeout_for_start_and_join() {
        let start = Cli::try_parse_from([
            "exochain",
            "start",
            "--round-timeout-ms",
            "7500",
            "--validator",
        ]);
        assert!(
            start.is_ok(),
            "start command must accept a bounded consensus round timeout"
        );

        let join = Cli::try_parse_from([
            "exochain",
            "join",
            "--seed",
            "seed1.exochain.io:4001",
            "--round-timeout-ms",
            "7500",
        ]);
        assert!(
            join.is_ok(),
            "join command must accept a bounded consensus round timeout"
        );

        assert!(
            Cli::try_parse_from(["exochain", "start", "--round-timeout-ms", "0"]).is_err(),
            "round timeout must reject zero-millisecond busy-loop values"
        );
        assert!(
            Cli::try_parse_from(["exochain", "start", "--round-timeout-ms", "300001"]).is_err(),
            "round timeout must reject deployment-stalling values above five minutes"
        );
    }

    #[test]
    fn node_bootstrap_uses_configured_round_timeout_not_fixed_literal() {
        let source = include_str!("main.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let reactor_config = production
            .split("let reactor_config = ReactorConfig")
            .nth(1)
            .and_then(|section| section.split("};").next())
            .expect("reactor config is constructed during node startup");

        assert!(!reactor_config.contains("round_timeout_ms: 5000"));
        assert!(reactor_config.contains("round_timeout_ms,"));
    }

    #[test]
    fn derive_quic_port_uses_adjacent_port_when_available() {
        assert_eq!(derive_quic_port(4001).unwrap(), 4002);
    }

    #[test]
    fn derive_quic_port_rejects_overflowing_port() {
        let err = derive_quic_port(u16::MAX).unwrap_err();
        let text = err.to_string();

        assert!(text.contains("65535"));
        assert!(text.contains("QUIC"));
    }

    #[test]
    fn main_crate_does_not_globally_suppress_as_conversion_lints() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(
            !production.contains("#![allow(clippy::as_conversions"),
            "main.rs must not globally suppress checked conversion lints"
        );
        assert!(
            !production.contains(".len() as u64"),
            "startup metrics must use checked length conversions"
        );
    }

    #[test]
    fn passport_router_is_strictly_authenticated_and_rate_limited() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let passport_source = include_str!("passport.rs");
        let passport_production = passport_source.split("#[cfg(test)]").next().unwrap();
        let passport_section = production
            .split("// Build the agent passport API router.")
            .nth(1)
            .and_then(|section| section.split("// Build the dashboard router").next())
            .unwrap();

        assert!(passport_section.contains("passport::passport_router("));
        assert!(
            passport_section.contains("bearer_auth.clone()"),
            "passport router must receive bearer auth directly, not only the global write guard"
        );
        assert!(
            passport_production.contains("ConcurrencyLimitLayer"),
            "passport router must have a router-local request limiter"
        );
        assert!(passport_production.contains("auth::require_bearer("));
        assert!(
            !passport_section.contains("require_bearer_on_writes"),
            "passport GET endpoints must not rely on write-only auth"
        );
    }

    #[tokio::test]
    async fn background_task_completion_is_ignored_until_failure() {
        let mut tasks = BackgroundTasks::new();
        tasks.spawn_one_shot("bounded startup task", async {});
        tasks.spawn_critical("short critical task", async {});

        let err = tasks.next_failure().await.unwrap_err();
        assert!(err.to_string().contains("short critical task"));

        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn background_task_panic_is_reported() {
        let mut tasks = BackgroundTasks::new();
        tasks.spawn_critical("panic task", async {
            panic!("supervised panic");
        });

        let err = tasks.next_failure().await.unwrap_err();
        assert!(err.to_string().contains("panicked"));

        tasks.shutdown().await;
    }

    #[test]
    fn startup_background_tasks_are_supervised() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(
            production.contains("BackgroundTasks"),
            "startup must register background tasks with a supervisor"
        );
        assert!(
            production.contains("tokio::select!"),
            "startup must race HTTP serving against supervised task failure"
        );
        assert!(
            !production.contains("tokio::spawn("),
            "startup must not discard JoinHandles from raw tokio::spawn"
        );
    }

    #[test]
    fn node_gateway_passes_database_pool_to_readiness_router() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gateway_section = production
            .split("let gateway_pool = gateway_pool_from_env().await?")
            .nth(1)
            .and_then(|section| section.split("let run_result = tokio::select!").next())
            .unwrap();

        assert!(
            production.contains("async fn gateway_pool_from_env()"),
            "node startup must initialize the gateway DB pool when DATABASE_URL is configured"
        );
        assert!(
            gateway_section.contains(
                "serve_with_extra_routes(\n        gateway_config,\n        Some(gateway_pool),"
            ),
            "node startup must pass the initialized DB pool to gateway readiness routes"
        );
        assert!(
            !gateway_section.contains("serve_with_extra_routes(gateway_config, None"),
            "node startup must not force /ready into no_db_configured state"
        );
    }

    #[test]
    fn avc_root_trust_loader_runs_before_router_construction() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let loader_index = production
            .find("load_configured_root_trust_bundle")
            .expect("AVC root trust loader call present");
        let router_index = production
            .find("let avc_router = avc::avc_router")
            .expect("AVC router construction present");
        assert!(
            loader_index < router_index,
            "AVC root trust issuer must be registered before AVC router construction"
        );
    }

    #[test]
    fn avc_registry_uses_gateway_database_pool_when_configured() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let pool_index = production
            .find("let gateway_pool = gateway_pool_from_env().await?")
            .expect("gateway pool initialization present");
        let avc_index = production
            .find("AvcApiState::with_durable_registry")
            .expect("AVC durable registry construction present");
        assert!(
            pool_index < avc_index,
            "DATABASE_URL-backed pool must be initialized before AVC durable registry startup"
        );
        assert!(
            production[avc_index..].contains("Some(gateway_pool.clone())"),
            "AVC durable registry must reuse the gateway database pool instead of requiring a separate /data-backed store"
        );
    }

    #[test]
    fn node_production_startup_uses_dagdb_store_not_sqlite_dag_db() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let start_node = production
            .split("async fn start_node(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("async fn load_configured_root_trust_bundle")
                    .next()
            })
            .expect("start_node source present");
        let status_branch = production
            .split("Command::Status { data_dir } =>")
            .nth(1)
            .and_then(|section| section.split("Command::Peers").next())
            .expect("status command source present");

        for (label, section) in [
            ("start_node", start_node),
            ("status command", status_branch),
        ] {
            assert!(
                !section.contains("SqliteDagStore::open"),
                "{label} must not open the legacy SQLite dag.db store in production"
            );
            assert!(
                !section.contains("dag.db"),
                "{label} must not reference the legacy SQLite dag.db file in production"
            );
        }
        assert!(
            start_node.contains("DagDbNodeStore::open"),
            "production node startup must open the DAG DB node store"
        );
        assert!(
            status_branch.contains("DagDbNodeStore::open"),
            "node status must read committed height from the DAG DB node store"
        );
    }

    #[test]
    fn zerodentity_restart_persists_dagdb_state() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let start_node = production
            .split("async fn start_node(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("async fn load_configured_root_trust_bundle")
                    .next()
            })
            .expect("start_node source present");
        let store_source = include_str!("zerodentity/store.rs");
        let store_production = store_source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("0dentity store production section present");

        assert!(
            start_node.contains("ZerodentityStore::open_dagdb"),
            "production node startup must open 0dentity through the DAG DB-backed store"
        );
        assert!(
            !start_node.contains("ZerodentityStore::open(data_dir)"),
            "production node startup must not open the memory-only 0dentity store"
        );
        assert!(
            store_production.contains("pub const ZERODENTITY_STORE_PERSISTENCE_READY: bool = true"),
            "0dentity persistence_ready() must become true only after DAG DB reload is wired"
        );
        for (family, variant) in [
            ("claim", "Claim"),
            ("score", "Score"),
            ("otp_challenge", "OtpChallenge"),
            ("otp_lockout", "OtpLockout"),
            ("attestation", "Attestation"),
            ("identity_session", "IdentitySession"),
            ("session_nonce", "SessionNonce"),
            ("dag_node", "DagNode"),
            ("trust_receipt", "TrustReceipt"),
        ] {
            assert!(
                store_production.contains(&format!("ZerodentityRecordFamily::{variant}"))
                    && store_production.contains(&format!("\"{family}\"")),
                "0dentity DAG DB persistence must cover {family} records"
            );
        }
    }

    #[test]
    fn avc_registry_startup_registers_all_resolved_validator_public_keys() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let avc_startup = production
            .split("let avc_state = Arc::new(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("match avc::load_configured_root_trust_bundle")
                    .next()
            })
            .expect("AVC startup section present");

        assert!(
            avc_startup.contains(
                "avc_state.register_validator_public_keys(sync_validator_public_keys.clone())"
            ),
            "AVC startup must register the full configured validator key set before durable receipt revalidation"
        );
        assert!(
            !avc_startup.contains("register_validator_public_key(node_identity.public_key)"),
            "AVC startup must not revalidate durable receipts against only the local node key"
        );
    }

    #[test]
    fn node_startup_requires_database_url_for_dagdb_node_store() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gateway_pool_from_env = production
            .split("async fn gateway_pool_from_env()")
            .nth(1)
            .and_then(|section| section.split("/// Start all subsystems").next())
            .expect("gateway_pool_from_env source present");
        let start_node = production
            .split("async fn start_node(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("async fn load_configured_root_trust_bundle")
                    .next()
            })
            .expect("start_node source present");

        assert!(
            gateway_pool_from_env.contains("required_env_value(\"DATABASE_URL\")"),
            "node startup must fail closed when DATABASE_URL is absent"
        );
        assert!(
            start_node.contains("let gateway_pool = gateway_pool_from_env().await?;"),
            "node startup must initialize the database pool before opening durable stores"
        );
        assert!(
            start_node.contains("DagDbNodeStore::open(")
                && start_node.contains("gateway_pool.clone()"),
            "node startup must use DATABASE_URL-backed DAG DB for canonical DAG state"
        );
        assert!(
            !start_node.contains("warn_avc_non_postgres_durability"),
            "node startup must not warn-and-fallback to local DAG persistence"
        );
    }

    #[test]
    fn node_gateway_database_pool_logging_does_not_expose_connection_string() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gateway_section = production
            .split("async fn gateway_pool_from_env()")
            .nth(1)
            .and_then(|section| section.split("if is_join").next())
            .unwrap();
        let gateway_logging = gateway_section
            .lines()
            .filter(|line| line.contains("tracing::"))
            .collect::<Vec<_>>()
            .join("\n");

        for forbidden in ["%database_url", "{database_url}", "database_url ="] {
            assert!(
                !gateway_logging.contains(forbidden),
                "gateway DB initialization logs must not expose the database URL"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod root_genesis_adapter_tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use exo_core::{Did, Hash256, SecretKey, Timestamp, crypto::KeyPair};
    use exo_root::{
        CeremonyEnvelope, CeremonyEnvelopeDraft, CeremonyPayloadKind, CeremonyPhase,
        CertifierContact, GenesisCeremonyConfig, PairwiseEncryptedPayload,
    };
    use tower::ServiceExt;

    use super::root_genesis::{RootGenesisApiState, root_genesis_router};

    fn did(index: u16) -> Did {
        Did::new(&format!("did:exo:root-portal-{index:02}")).expect("valid DID")
    }

    fn certifier(index: u16) -> (CertifierContact, SecretKey) {
        let keypair = KeyPair::from_secret_bytes([u8::try_from(index).expect("index fits"); 32])
            .expect("valid keypair");
        let transport_secret = [u8::try_from(index).expect("index fits"); 32];
        let transport_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(transport_secret));
        (
            CertifierContact {
                did: did(index),
                frost_identifier: index,
                signing_public_key: *keypair.public_key(),
                transport_public_key: *transport_public.as_bytes(),
            },
            keypair.secret_key().clone(),
        )
    }

    fn config() -> (GenesisCeremonyConfig, SecretKey) {
        let mut certifiers = Vec::new();
        let mut first_secret = None;
        for index in 1..=13 {
            let (contact, secret) = certifier(index);
            if index == 1 {
                first_secret = Some(secret.clone());
            }
            certifiers.push(contact);
        }
        (
            GenesisCeremonyConfig {
                ceremony_id: "exo-root-portal-test".into(),
                network_id: "exochain-test".into(),
                repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
                constitution_hash: Hash256::digest(b"constitution"),
                threshold: 7,
                max_signers: 13,
                created_at: Timestamp::new(1_785_000_000_000, 0),
                certifiers,
                signing_set: (1..=7).collect(),
            },
            first_secret.expect("first certifier secret"),
        )
    }

    async fn post_envelope(
        router: axum::Router,
        envelope: &CeremonyEnvelope,
    ) -> axum::response::Response {
        let body = serde_json::to_vec(envelope).expect("json body");
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/root-genesis/portal/envelopes")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    fn encrypted_payload_bytes(ciphertext: impl Into<Vec<u8>>) -> Vec<u8> {
        let payload = PairwiseEncryptedPayload {
            nonce: [1u8; 24],
            ciphertext: ciphertext.into(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).expect("encrypted payload encoding");
        bytes
    }

    #[tokio::test]
    async fn root_genesis_portal_handler_accepts_signed_envelope_and_rejects_replay() {
        let (config, secret) = config();
        let sender = config.certifiers[0].did.clone();
        let recipient = config.certifiers[1].did.clone();
        let state = RootGenesisApiState::new(config.clone());
        let router = root_genesis_router(state);
        let envelope = CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round2,
                payload_kind: CeremonyPayloadKind::Round2EncryptedPackage,
                sender_did: sender,
                recipient_did: Some(recipient),
                sequence: 1,
                payload_bytes: encrypted_payload_bytes(b"ciphertext"),
            },
            &secret,
        )
        .expect("signed envelope");

        let accepted = post_envelope(router.clone(), &envelope).await;
        assert_eq!(accepted.status(), StatusCode::CREATED);

        let replay = post_envelope(router, &envelope).await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn root_genesis_portal_handler_rejects_plaintext_round_two_payload() {
        let (config, secret) = config();
        let sender = config.certifiers[0].did.clone();
        let recipient = config.certifiers[1].did.clone();
        let router = root_genesis_router(RootGenesisApiState::new(config.clone()));
        let envelope = CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round2,
                payload_kind: CeremonyPayloadKind::Round2PlaintextPackage,
                sender_did: sender,
                recipient_did: Some(recipient),
                sequence: 2,
                payload_bytes: b"raw share".to_vec(),
            },
            &secret,
        )
        .expect("signed envelope");

        let response = post_envelope(router, &envelope).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
