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

#![allow(clippy::as_conversions, clippy::type_complexity)]

mod api;
mod auth;
mod challenges;
mod cli;
mod config;
mod dashboard;
mod exoforge;
mod governance_feedback;
mod holons;
mod identity;
mod metrics;
mod network;
mod passport;
mod provenance;
mod reactor;
mod receipt_dashboard;
mod sentinels;
mod store;
mod sync;
mod telegram;
mod wire;
mod zerodentity;

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use clap::Parser;
use cli::{Cli, Command};
use exo_core::types::Did;
use holons::{HolonEvent, HolonManagerConfig};
use network::{NetworkConfig, NetworkEvent, NetworkHandle};
use reactor::{ReactorConfig, ReactorEvent};
use sync::{SyncConfig, SyncEngine, SyncEvent};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    // Install a panic hook that logs via tracing before aborting.
    // Without this, panics print to stderr only, invisible to structured log
    // collectors (Grafana Loki, Datadog, etc.).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<unknown>");
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".into());
        eprintln!("PANIC at {location}: {msg}");
        default_hook(info);
    }));

    // Structured logging with RUST_LOG env filter support.
    // Default: info for exochain crates, warn for everything else.
    #[allow(clippy::expect_used)] // Constant string, parse cannot fail.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "warn,exochain=info,exo_node=info,exo_gateway=info"
                    .parse()
                    .expect("valid filter")
            }),
        )
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

/// Parse a list of validator DID strings, falling back to just this node's DID.
fn parse_validator_set(cli_validators: &Option<Vec<String>>, node_did: &Did) -> BTreeSet<Did> {
    if let Some(vals) = cli_validators {
        vals.iter()
            .filter_map(|s| match Did::new(s) {
                Ok(d) => Some(d),
                Err(e) => {
                    tracing::warn!(did = %s, err = %e, "Invalid validator DID — skipping");
                    None
                }
            })
            .collect()
    } else {
        // Default: this node is the sole validator (standalone mode).
        let mut set = BTreeSet::new();
        set.insert(node_did.clone());
        set
    }
}

/// Spawn the event fan-out task that dispatches network events to both
/// the consensus reactor and the sync engine.
fn spawn_event_fanout(
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    reactor_tx: mpsc::Sender<NetworkEvent>,
    sync_tx: mpsc::Sender<NetworkEvent>,
    metrics: metrics::SharedMetrics,
) {
    tokio::spawn(async move {
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
            let _ = reactor_tx.send(event.clone()).await;
            // Dispatch to sync engine (state sync messages).
            let _ = sync_tx.send(event).await;
        }
    });
}

/// Start all subsystems for a running node.
async fn start_node(
    data_dir: &std::path::Path,
    api_port: u16,
    p2p_port: u16,
    validator: bool,
    validators: &Option<Vec<String>>,
    seed_addrs: Vec<libp2p::Multiaddr>,
    is_join: bool,
) -> anyhow::Result<()> {
    // Bootstrap node identity.
    let node_identity = identity::load_or_create(data_dir)?;
    tracing::info!(
        did = %node_identity.did,
        pubkey = hex::encode(node_identity.public_key_bytes()),
        "Node identity ready"
    );

    // Open local DAG store.
    let dag_store = store::SqliteDagStore::open(data_dir)?;
    let height = dag_store.committed_height_value();
    tracing::info!(height, "DAG store opened");

    // Open 0dentity store (shares the same dag.db, applies zerodentity migration).
    let zerodentity_store = zerodentity::store::ZerodentityStore::open(data_dir)?;
    let zerodentity_store = std::sync::Arc::new(Mutex::new(zerodentity_store));
    tracing::info!("0dentity store ready");

    tracing::info!(
        api_port,
        p2p_port,
        validator,
        did = %node_identity.did,
        "Starting exochain node"
    );

    // Start P2P networking.
    let net_config = NetworkConfig {
        tcp_port: p2p_port,
        quic_port: p2p_port + 1,
        seed_addrs: seed_addrs.clone(),
        node_did: node_identity.did.clone(),
    };

    let mut swarm = network::build_swarm(&net_config)?;
    network::start_listening(&mut swarm, &net_config)?;

    // Dial seed nodes if joining.
    if is_join && !net_config.seed_addrs.is_empty() {
        let dialed = network::dial_seeds(&mut swarm, &net_config.seed_addrs)?;
        tracing::info!(dialed, "Dialed seed nodes");
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(256);
    let net_handle = NetworkHandle::new(cmd_tx);

    // Spawn the P2P network event loop.
    tokio::spawn(network::run_network_loop(swarm, cmd_rx, event_tx));
    tracing::info!(p2p_port, "P2P network started");

    // Create shared state.
    let shared_store = Arc::new(Mutex::new(dag_store));

    // Create metrics registry.
    let node_metrics = metrics::create_metrics();

    // --- Consensus reactor ---
    let validator_set = parse_validator_set(validators, &node_identity.did);
    let reactor_config = ReactorConfig {
        node_did: node_identity.did.clone(),
        is_validator: validator,
        validators: validator_set.clone(),
        round_timeout_ms: 5000,
    };

    let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> = {
        let identity = identity::load_or_create(data_dir)?;
        Arc::new(move |data: &[u8]| identity.sign(data))
    };

    let reactor_state =
        reactor::create_reactor_state(&reactor_config, sign_fn, Some(&shared_store));
    let (reactor_tx, mut reactor_rx) = mpsc::channel::<ReactorEvent>(256);
    let (reactor_event_tx, reactor_event_rx) = mpsc::channel::<NetworkEvent>(256);

    tokio::spawn(reactor::run_reactor(
        reactor_state.clone(),
        Arc::clone(&shared_store),
        net_handle.clone(),
        reactor_event_rx,
        reactor_tx,
    ));

    // Set initial metrics from configuration.
    node_metrics
        .is_validator
        .store(u64::from(validator), std::sync::atomic::Ordering::Relaxed);
    node_metrics.validator_count.store(
        validator_set.len() as u64,
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
                chunk_size: 100,
                max_sync_nodes: 200,
            },
            Arc::clone(&shared_store),
            net_handle.clone(),
            mpsc::channel::<SyncEvent>(1).0,
        );
        tokio::spawn(async move {
            // Wait briefly for connections to establish.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Err(e) = sync_for_join.request_sync().await {
                tracing::warn!(err = %e, "Failed to initiate state sync");
            }
        });
    }

    // Spawn the sync engine event loop.
    tokio::spawn(sync::run_sync_engine(sync_engine, sync_net_event_rx));
    tracing::info!("Sync engine started");

    // --- Event fan-out ---
    spawn_event_fanout(
        event_rx,
        reactor_event_tx,
        sync_net_event_tx,
        Arc::clone(&node_metrics),
    );

    // --- Event loggers (with metrics updates) ---
    let reactor_metrics = Arc::clone(&node_metrics);
    tokio::spawn(async move {
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
    tokio::spawn(async move {
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
    let holon_config = HolonManagerConfig {
        node_did: node_identity.did.clone(),
        root_did: Did::new("did:exo:root").unwrap_or_else(|_| node_identity.did.clone()),
        topology_interval_secs: 60,
        scaling_interval_secs: 300,
        health_interval_secs: 30,
    };

    let (holon_event_tx, mut holon_event_rx) = mpsc::channel::<HolonEvent>(256);
    let (holon_feedback_tx, holon_feedback_rx) = mpsc::channel::<HolonEvent>(256);

    tokio::spawn(holons::run_holon_manager(
        holon_config,
        Arc::clone(&reactor_state),
        Arc::clone(&shared_store),
        net_handle.clone(),
        holon_event_tx,
    ));
    tracing::info!("Infrastructure Holons started (topology, scaling, health)");

    // Holon event fan-out: logs + metrics, then forwards to governance feedback.
    let holon_metrics = Arc::clone(&node_metrics);
    tokio::spawn(async move {
        while let Some(event) = holon_event_rx.recv().await {
            // Forward to governance feedback loop (non-blocking).
            let _ = holon_feedback_tx.try_send(event.clone());

            match event {
                HolonEvent::TopologyAnalysis {
                    peer_count,
                    diversity_score,
                    recommendation,
                } => {
                    holon_metrics
                        .peer_count
                        .store(peer_count as u64, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        peer_count,
                        diversity_score,
                        %recommendation,
                        "Topology Holon"
                    );
                }
                HolonEvent::ScalingRecommendation {
                    validator_count,
                    node_count,
                    recommendation,
                } => {
                    holon_metrics
                        .validator_count
                        .store(validator_count as u64, std::sync::atomic::Ordering::Relaxed);
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
                    ref status,
                } => match status {
                    holons::HealthStatus::Healthy => {
                        tracing::debug!(consensus_round, committed_height, "Health Holon: healthy");
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
                HolonEvent::HolonTerminated {
                    ref holon_id,
                    ref reason,
                } => {
                    tracing::error!(
                        %holon_id,
                        %reason,
                        "Infrastructure Holon terminated"
                    );
                }
            }
        }
    });

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
    let api_state = Arc::new(api::NodeApiState {
        reactor_state: Arc::clone(&reactor_state),
        store: Arc::clone(&shared_store),
        net_handle: net_handle.clone(),
    });
    let governance_router = api::governance_router(api_state);

    // Build the agent passport API router.
    let passport_state = Arc::new(passport::PassportApiState {
        reactor_state: Arc::clone(&reactor_state),
        store: Arc::clone(&shared_store),
        zerodentity_store: Arc::clone(&zerodentity_store),
    });
    let passport_router = passport::passport_router(passport_state);

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
    let forge_state: exoforge::SharedForgeState =
        Arc::new(Mutex::new(exoforge::ForgeState::new_zerodentity()));
    let forge_router = exoforge::exoforge_router(forge_state);
    tracing::info!("ExoForge initialized — 0dentity spec loaded, 56 tasks across 12 phases");

    // Build the sentinel API router and start the sentinel loop.
    let sentinel_state: sentinels::SharedSentinelState =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let sentinel_router = sentinels::sentinel_router(Arc::clone(&sentinel_state));
    let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel::<sentinels::SentinelAlert>(64);
    let (alert_feedback_tx, alert_feedback_rx) =
        tokio::sync::mpsc::channel::<sentinels::SentinelAlert>(64);

    // Spawn sentinel background loop.
    tokio::spawn(sentinels::run_sentinel_loop(
        Arc::clone(&reactor_state),
        Arc::clone(&shared_store),
        Arc::clone(&zerodentity_store),
        Arc::clone(&sentinel_state),
        alert_tx,
        std::time::Duration::from_secs(30),
    ));

    // Start the Telegram adjutant if configured.
    // Fan-out: alerts go to both Telegram (human) and governance feedback (autonomous).
    if let Some(tg_config) = telegram::AdjutantConfig::from_env() {
        tracing::info!("Telegram adjutant configured — starting bot");
        let adjutant = telegram::Adjutant::new(tg_config);
        let (tg_alert_tx, tg_alert_rx) = tokio::sync::mpsc::channel::<sentinels::SentinelAlert>(64);
        // Fan-out task: duplicates alerts to both Telegram and governance feedback.
        tokio::spawn(async move {
            while let Some(alert) = alert_rx.recv().await {
                let _ = tg_alert_tx.try_send(alert.clone());
                let _ = alert_feedback_tx.try_send(alert);
            }
        });
        tokio::spawn(telegram::run_adjutant(
            adjutant,
            tg_alert_rx,
            Arc::clone(&reactor_state),
            Arc::clone(&shared_store),
            Arc::clone(&challenge_store),
            Arc::clone(&sentinel_state),
            Arc::clone(&zerodentity_store),
        ));
    } else {
        tracing::info!(
            "Telegram adjutant not configured — governance feedback loop will receive alerts directly"
        );
        // Fan-out without Telegram: only governance feedback gets alerts.
        tokio::spawn(async move {
            while let Some(alert) = alert_rx.recv().await {
                let _ = alert_feedback_tx.try_send(alert);
            }
        });
    }

    // Spawn the governance feedback loop — closes the self-improvement circuit.
    // Sentinel alerts and holon events feed into auto-proposals with trust receipts.
    tokio::spawn(governance_feedback::run_feedback_loop(
        alert_feedback_rx,
        holon_feedback_rx,
        Arc::clone(&reactor_state),
        Arc::clone(&shared_store),
        net_handle.clone(),
    ));
    tracing::info!("Governance feedback loop active — autonomous self-improvement enabled");

    // Generate admin token for write-endpoint authentication.
    let admin_token = auth::generate_admin_token();
    tracing::info!(
        admin_token = %admin_token,
        "Admin bearer token generated — required for POST endpoints"
    );
    let bearer_auth = auth::BearerAuth {
        token: Arc::new(admin_token),
    };

    // Build 0dentity routers.
    let zd_onboarding_state = zerodentity::onboarding::OnboardingState {
        store: std::sync::Arc::clone(&zerodentity_store),
    };
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let zd_api_state = zerodentity::api::ApiState {
        store: std::sync::Arc::clone(&zerodentity_store),
        node_did: node_identity.did.clone(),
        started_ms,
    };
    let zerodentity_onboarding_router =
        zerodentity::onboarding::onboarding_router(zd_onboarding_state);
    let zerodentity_api_router = zerodentity::api::zerodentity_api_router(zd_api_state);
    let zerodentity_dashboard_router = zerodentity::dashboard::zerodentity_dashboard_router();
    let zerodentity_onboarding_ui_router =
        zerodentity::onboarding_ui::zerodentity_onboarding_router();
    tracing::info!(
        "0dentity routers ready — /0dentity, /0dentity/dashboard/:did, /api/v1/0dentity/*"
    );

    // Merge metrics + governance + passport + dashboard into a single extra router.
    // Layers (outermost first):
    //   1. TraceLayer — structured request/response spans for observability
    //   2. Timeout — 30s hard limit prevents resource exhaustion
    //   3. Body limit — 1 MiB max request body prevents memory exhaustion
    //   4. Rate limiter — 60 writes/min per IP (protects governance API)
    //   5. Bearer auth — protects POST/PUT/DELETE, allows GET
    // NOTE: /health and /ready are provided by the gateway's own router.
    let write_limiter = auth::WriteRateLimiter::new(60, 60);
    let extra_router = metrics_router
        .merge(governance_router)
        .merge(passport_router)
        .merge(dashboard_router)
        .merge(challenge_router)
        .merge(provenance_router)
        .merge(receipt_dashboard_router)
        .merge(sentinel_router)
        .merge(forge_router)
        .merge(zerodentity_onboarding_router)
        .merge(zerodentity_api_router)
        .merge(zerodentity_dashboard_router)
        .merge(zerodentity_onboarding_ui_router)
        .layer(axum::middleware::from_fn(move |req, next| {
            let a = bearer_auth.clone();
            auth::require_bearer_on_writes(a, req, next)
        }))
        .layer(axum::middleware::from_fn(move |req, next| {
            let l = write_limiter.clone();
            auth::rate_limit_writes(l, req, next)
        }))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            1024 * 1024, // 1 MiB
        ))
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(30),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // Start the gateway HTTP server (blocks).
    let bind_address = format!("0.0.0.0:{api_port}");
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

    exo_gateway::server::serve_with_extra_routes(gateway_config, None, Some(extra_router)).await?;
    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Start {
            api_port,
            p2p_port,
            data_dir,
            validator,
            validators,
        } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let cfg = config::load_or_create(&data_dir)?;

            let api_port = api_port.unwrap_or(cfg.api_port);
            let p2p_port = p2p_port.unwrap_or(cfg.p2p_port);

            start_node(
                &data_dir,
                api_port,
                p2p_port,
                validator,
                &validators,
                vec![],
                false,
            )
            .await
        }

        Command::Join {
            seed,
            api_port,
            p2p_port,
            data_dir,
            validator,
            validators,
        } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let cfg = config::load_or_create(&data_dir)?;

            let api_port = api_port.unwrap_or(cfg.api_port);
            let p2p_port = p2p_port.unwrap_or(cfg.p2p_port);

            // Parse seed addresses into multiaddrs.
            let seed_addrs: Vec<libp2p::Multiaddr> = seed
                .iter()
                .filter_map(|s| {
                    if s.starts_with('/') {
                        s.parse().ok()
                    } else {
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() == 2 {
                            format!("/ip4/{}/tcp/{}", parts[0], parts[1]).parse().ok()
                        } else {
                            tracing::warn!(seed = %s, "Invalid seed address format");
                            None
                        }
                    }
                })
                .collect();

            start_node(
                &data_dir,
                api_port,
                p2p_port,
                validator,
                &validators,
                seed_addrs,
                true,
            )
            .await
        }

        Command::Status { data_dir } => {
            let data_dir = config::resolve_data_dir(data_dir)?;
            let node_identity = identity::load_or_create(&data_dir)?;
            let dag_store = store::SqliteDagStore::open(&data_dir)?;

            println!("Node:   {}", node_identity.did);
            println!("Height: {}", dag_store.committed_height_value());
            println!("Data:   {}", data_dir.display());

            Ok(())
        }

        Command::Peers { data_dir: _ } => {
            println!("Peer listing requires a running node. Use `exochain start` first.");
            Ok(())
        }
    }
}
