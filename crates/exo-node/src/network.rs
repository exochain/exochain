//! P2P networking layer — libp2p swarm with gossipsub, Kademlia, mDNS, and identify.
//!
//! This module bridges the existing `exo-api::p2p` abstractions (PeerRegistry,
//! ASN diversity, rate limiting) with a real libp2p transport layer.

#![allow(
    clippy::expect_used,
    clippy::large_enum_variant,
    clippy::collapsible_match
)]

use std::time::Duration;

use exo_api::p2p::{PeerId as ExoPeerId, PeerInfo, PeerRegistry, RateLimiter};
use exo_core::{
    hash::hash_structured,
    types::{Did, Hash256, Timestamp},
};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, gossipsub, identify, kad, mdns, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tokio::sync::mpsc;

use crate::wire::{self, WireMessage, topics};

const GOSSIPSUB_MESSAGE_ID_DOMAIN: &str = "exo.node.gossipsub.message-id.v1";

#[derive(serde::Serialize)]
struct GossipsubMessageIdPayload<'a> {
    domain: &'static str,
    topic: &'a str,
    data: &'a [u8],
}

// ---------------------------------------------------------------------------
// Composed network behaviour
// ---------------------------------------------------------------------------

/// Composed libp2p behaviour for exochain nodes.
#[derive(NetworkBehaviour)]
pub struct ExochainBehaviour {
    /// Pub/sub for consensus and governance broadcasts.
    pub gossipsub: gossipsub::Behaviour,
    /// Distributed hash table for peer discovery.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Local network discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Protocol metadata exchange.
    pub identify: identify::Behaviour,
    /// Keepalive pings.
    pub ping: ping::Behaviour,
}

// ---------------------------------------------------------------------------
// Network manager
// ---------------------------------------------------------------------------

/// Commands sent from the application layer to the network task.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Publish a wire message to a gossipsub topic.
    Publish { topic: String, message: WireMessage },
    /// Dial a peer at a multiaddr.
    #[allow(dead_code)] // Used when governance API enables dynamic peer dialing
    Dial { addr: Multiaddr },
    /// Request the current peer count.
    #[cfg_attr(not(feature = "unaudited-infrastructure-holons"), allow(dead_code))]
    PeerCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
}

/// Events emitted from the network task to the application layer.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A wire message was received via gossipsub.
    MessageReceived {
        source: PeerId,
        topic: String,
        message: WireMessage,
    },
    /// A new peer was discovered.
    PeerDiscovered { peer_id: PeerId },
    /// A peer disconnected.
    PeerLost { peer_id: PeerId },
}

/// Configuration for the network layer.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port to listen on for TCP.
    pub tcp_port: u16,
    /// Port to listen on for QUIC (UDP).
    pub quic_port: u16,
    /// Seed node multiaddrs to dial on startup.
    pub seed_addrs: Vec<Multiaddr>,
    /// This node's DID (for protocol identification).
    pub node_did: Did,
}

/// Build the libp2p swarm with all behaviours composed.
pub fn build_swarm(config: &NetworkConfig) -> anyhow::Result<Swarm<ExochainBehaviour>> {
    let node_did_for_identify = config.node_did.to_string();
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|keypair| {
            // Gossipsub configuration
            let message_id_fn = canonical_gossipsub_message_id;

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|e| std::io::Error::other(format!("gossipsub config: {e}")))?;

            let mut gossipsub_behaviour = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            )
            .map_err(|e| std::io::Error::other(format!("gossipsub: {e}")))?;

            // Subscribe to exochain topics
            let consensus_topic = gossipsub::IdentTopic::new(topics::CONSENSUS);
            let governance_topic = gossipsub::IdentTopic::new(topics::GOVERNANCE);
            let peers_topic = gossipsub::IdentTopic::new(topics::PEER_EXCHANGE);

            gossipsub_behaviour
                .subscribe(&consensus_topic)
                .map_err(|e| std::io::Error::other(format!("subscribe consensus: {e}")))?;
            gossipsub_behaviour
                .subscribe(&governance_topic)
                .map_err(|e| std::io::Error::other(format!("subscribe governance: {e}")))?;
            gossipsub_behaviour
                .subscribe(&peers_topic)
                .map_err(|e| std::io::Error::other(format!("subscribe peers: {e}")))?;

            // Kademlia DHT for peer discovery
            let peer_id = keypair.public().to_peer_id();
            let kademlia = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));

            // mDNS for local network discovery
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .map_err(|e| std::io::Error::other(format!("mdns: {e}")))?;

            // Identify protocol for exchanging metadata.
            // Include the node DID in the agent version for diagnostics.
            let identify = identify::Behaviour::new(
                identify::Config::new("/exochain/1.0.0".into(), keypair.public())
                    .with_agent_version(format!("exochain/1.0 {node_did_for_identify}"))
                    .with_push_listen_addr_updates(true),
            );

            // Ping for keepalive
            let ping = ping::Behaviour::default();

            Ok(ExochainBehaviour {
                gossipsub: gossipsub_behaviour,
                kademlia,
                mdns,
                identify,
                ping,
            })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    Ok(swarm)
}

fn canonical_gossipsub_message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    match canonical_gossipsub_message_id_for_parts(message.topic.as_str(), &message.data) {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(
                err = %error,
                "failed to encode canonical gossipsub message id payload"
            );
            gossipsub::MessageId::new(b"exo.node.gossipsub.message-id.serialization-error")
        }
    }
}

fn canonical_gossipsub_message_id_for_parts(
    topic: &str,
    data: &[u8],
) -> anyhow::Result<gossipsub::MessageId> {
    let payload = GossipsubMessageIdPayload {
        domain: GOSSIPSUB_MESSAGE_ID_DOMAIN,
        topic,
        data,
    };
    let hash = hash_structured(&payload)
        .map_err(|error| anyhow::anyhow!("canonical gossipsub message id encoding: {error}"))?;
    Ok(gossipsub::MessageId::new(hash.as_bytes()))
}

/// Start listening on configured ports.
pub fn start_listening(
    swarm: &mut Swarm<ExochainBehaviour>,
    config: &NetworkConfig,
) -> anyhow::Result<()> {
    // Listen on TCP
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.tcp_port).parse()?;
    swarm.listen_on(tcp_addr)?;

    // Listen on QUIC
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.quic_port).parse()?;
    swarm.listen_on(quic_addr)?;

    Ok(())
}

/// Dial seed nodes.
pub fn dial_seeds(
    swarm: &mut Swarm<ExochainBehaviour>,
    seeds: &[Multiaddr],
) -> anyhow::Result<usize> {
    let mut dialed = 0;
    for addr in seeds {
        match swarm.dial(addr.clone()) {
            Ok(()) => {
                tracing::info!(%addr, "Dialing seed node");
                dialed += 1;
            }
            Err(e) => {
                tracing::warn!(%addr, err = %e, "Failed to dial seed");
            }
        }
    }
    Ok(dialed)
}

/// Run the network event loop as a Tokio task.
///
/// This task:
/// 1. Processes libp2p swarm events (connections, messages, discovery)
/// 2. Bridges mDNS discoveries to gossipsub
/// 3. Forwards received gossipsub messages as `NetworkEvent`s
/// 4. Handles `NetworkCommand`s from the application layer
pub async fn run_network_loop(
    mut swarm: Swarm<ExochainBehaviour>,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
) {
    let mut peer_registry = PeerRegistry::new();
    let mut rate_limiter = RateLimiter::new();

    loop {
        tokio::select! {
            // Process swarm events
            event = swarm.select_next_some() => {
                match event {
                    // -- Connection events --
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let local_peer = *swarm.local_peer_id();
                        tracing::info!(%address, peer_id = %local_peer, "Listening");
                    }

                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        tracing::info!(%peer_id, "Connection established");
                        register_peer(&mut peer_registry, &peer_id);
                        if event_tx
                            .send(NetworkEvent::PeerDiscovered { peer_id })
                            .await
                            .is_err()
                        {
                            tracing::warn!("Network event receiver dropped (PeerDiscovered)");
                        }
                    }

                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        tracing::info!(%peer_id, "Connection closed");
                        if event_tx
                            .send(NetworkEvent::PeerLost { peer_id })
                            .await
                            .is_err()
                        {
                            tracing::warn!("Network event receiver dropped (PeerLost)");
                        }
                    }

                    // -- Gossipsub events --
                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message {
                            propagation_source,
                            message,
                            ..
                        }
                    )) => {
                        let exo_peer = libp2p_peer_to_exo(&propagation_source);

                        // Rate limiting using existing exo-api RateLimiter
                        if rate_limiter.check_and_increment(&exo_peer).is_err() {
                            tracing::warn!(
                                peer = %propagation_source,
                                "Rate limited — dropping message"
                            );
                            continue;
                        }

                        let topic_str = message.topic.to_string();
                        match wire::decode(&message.data) {
                            Ok(wire_msg) => {
                                if event_tx
                                    .send(NetworkEvent::MessageReceived {
                                        source: propagation_source,
                                        topic: topic_str,
                                        message: wire_msg,
                                    })
                                    .await
                                    .is_err()
                                {
                                    tracing::warn!(
                                        "Network event receiver dropped (MessageReceived)"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    peer = %propagation_source,
                                    err = %e,
                                    "Failed to decode wire message"
                                );
                            }
                        }
                    }

                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        tracing::debug!(%peer_id, %topic, "Peer subscribed to topic");
                    }

                    // -- mDNS events —- bridge discovered peers to gossipsub
                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Mdns(
                        mdns::Event::Discovered(peers)
                    )) => {
                        for (peer_id, addr) in peers {
                            tracing::info!(%peer_id, %addr, "mDNS discovered peer");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            register_peer(&mut peer_registry, &peer_id);
                            if event_tx
                                .send(NetworkEvent::PeerDiscovered { peer_id })
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    "Network event receiver dropped (mDNS PeerDiscovered)"
                                );
                            }
                        }
                    }

                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Mdns(
                        mdns::Event::Expired(peers)
                    )) => {
                        for (peer_id, _addr) in peers {
                            tracing::debug!(%peer_id, "mDNS peer expired");
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }

                    // -- Identify events --
                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        tracing::debug!(
                            %peer_id,
                            protocol = %info.protocol_version,
                            agent = %info.agent_version,
                            "Identified peer"
                        );
                        // Add identified addresses to Kademlia
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }

                    // -- Kademlia events --
                    SwarmEvent::Behaviour(ExochainBehaviourEvent::Kademlia(
                        kad::Event::RoutingUpdated { peer, .. }
                    )) => {
                        tracing::debug!(%peer, "Kademlia routing updated");
                    }

                    _ => {}
                }
            }

            // Process application commands
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    NetworkCommand::Publish { topic, message } => {
                        match wire::encode(&message) {
                            Ok(bytes) => {
                                let topic = gossipsub::IdentTopic::new(topic);
                                match swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                    Ok(msg_id) => {
                                        tracing::debug!(%msg_id, "Published message");
                                    }
                                    Err(e) => {
                                        tracing::warn!(err = %e, "Failed to publish");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(err = %e, "Failed to encode message");
                            }
                        }
                    }

                    NetworkCommand::Dial { addr } => {
                        match swarm.dial(addr.clone()) {
                            Ok(()) => {
                                tracing::info!(%addr, "Dialing peer");
                            }
                            Err(e) => {
                                tracing::warn!(%addr, err = %e, "Failed to dial");
                            }
                        }
                    }

                    NetworkCommand::PeerCount { reply } => {
                        let count = swarm.connected_peers().count();
                        if reply.send(count).is_err() {
                            tracing::warn!("PeerCount reply receiver dropped");
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Peer bridge helpers
// ---------------------------------------------------------------------------

/// Convert a libp2p PeerId to an exochain PeerId (DID-based).
fn libp2p_peer_to_exo(peer_id: &PeerId) -> ExoPeerId {
    let did_str = format!("did:exo:peer-{}", peer_id);
    ExoPeerId(Did::new(&did_str).unwrap_or_else(|_| {
        // Fallback: use the hash of the peer ID
        let hash = blake3::hash(peer_id.to_bytes().as_slice());
        Did::new(&format!(
            "did:exo:peer-{}",
            hex::encode(&hash.as_bytes()[..16])
        ))
        .expect("fallback DID must be valid")
    }))
}

/// Register a libp2p peer in the exochain PeerRegistry.
fn register_peer(registry: &mut PeerRegistry, peer_id: &PeerId) {
    let exo_peer = libp2p_peer_to_exo(peer_id);
    if registry.get(&exo_peer).is_none() {
        registry.register(PeerInfo {
            id: exo_peer,
            addresses: vec![peer_id.to_string()],
            public_key_hash: Hash256::ZERO,
            last_seen: Timestamp::ZERO,
            reputation_score: 50,
        });
    }
}

// ---------------------------------------------------------------------------
// Network handle for the application layer
// ---------------------------------------------------------------------------

/// Handle for sending commands to the network task.
#[derive(Clone)]
pub struct NetworkHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
}

impl NetworkHandle {
    /// Create a new handle from a command sender.
    #[must_use]
    pub fn new(cmd_tx: mpsc::Sender<NetworkCommand>) -> Self {
        Self { cmd_tx }
    }

    /// Publish a wire message to a gossipsub topic.
    pub async fn publish(&self, topic: &str, message: WireMessage) -> anyhow::Result<()> {
        self.cmd_tx
            .send(NetworkCommand::Publish {
                topic: topic.to_string(),
                message,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Network task has stopped"))
    }

    /// Dial a peer at a multiaddr.
    #[allow(dead_code)] // Used when governance API enables dynamic peer dialing
    pub async fn dial(&self, addr: Multiaddr) -> anyhow::Result<()> {
        self.cmd_tx
            .send(NetworkCommand::Dial { addr })
            .await
            .map_err(|_| anyhow::anyhow!("Network task has stopped"))
    }

    /// Get the current connected peer count.
    #[cfg_attr(not(feature = "unaudited-infrastructure-holons"), allow(dead_code))]
    pub async fn peer_count(&self) -> anyhow::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::PeerCount { reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Network task has stopped"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("Network task dropped reply"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn libp2p_peer_to_exo_deterministic() {
        let peer_id = PeerId::random();
        let exo1 = libp2p_peer_to_exo(&peer_id);
        let exo2 = libp2p_peer_to_exo(&peer_id);
        assert_eq!(exo1, exo2);
    }

    #[test]
    fn register_peer_no_duplicates() {
        let mut registry = PeerRegistry::new();
        let peer_id = PeerId::random();
        register_peer(&mut registry, &peer_id);
        register_peer(&mut registry, &peer_id);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_different_peers() {
        let mut registry = PeerRegistry::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        register_peer(&mut registry, &p1);
        register_peer(&mut registry, &p2);
        assert_eq!(registry.len(), 2);
    }

    #[tokio::test]
    async fn build_swarm_succeeds() {
        let config = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:test").unwrap(),
        };
        let swarm = build_swarm(&config);
        assert!(swarm.is_ok());
    }

    #[test]
    fn production_gossipsub_message_ids_do_not_use_default_hasher() {
        let source = include_str!("network.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source section exists");
        assert!(
            !production.contains("DefaultHasher"),
            "gossipsub message IDs must not use process-seeded DefaultHasher"
        );
    }

    #[test]
    fn gossipsub_message_ids_are_canonical_and_domain_separated() {
        let id_a = canonical_gossipsub_message_id_for_parts("exo/consensus", b"payload")
            .expect("canonical message id");
        let id_b = canonical_gossipsub_message_id_for_parts("exo/consensus", b"payload")
            .expect("canonical message id");
        let different_topic =
            canonical_gossipsub_message_id_for_parts("exo/governance", b"payload")
                .expect("canonical message id");
        let different_payload = canonical_gossipsub_message_id_for_parts("exo/consensus", b"other")
            .expect("canonical message id");

        assert_eq!(id_a, id_b);
        assert_ne!(id_a, different_topic);
        assert_ne!(id_a, different_payload);

        let expected = hash_structured(&GossipsubMessageIdPayload {
            domain: GOSSIPSUB_MESSAGE_ID_DOMAIN,
            topic: "exo/consensus",
            data: b"payload",
        })
        .expect("canonical hash");
        assert_eq!(id_a.to_string(), expected.to_string());
    }

    #[tokio::test]
    async fn network_handle_peer_count() {
        let config = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:test").unwrap(),
        };
        let swarm = build_swarm(&config).unwrap();

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = mpsc::channel(32);

        let handle = NetworkHandle::new(cmd_tx);

        // Spawn network loop
        tokio::spawn(run_network_loop(swarm, cmd_rx, event_tx));

        // Query peer count before listening so concurrent network tests cannot
        // connect through loopback/mDNS and make this assertion nondeterministic.
        let count = handle.peer_count().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn two_nodes_connect_via_dial() {
        // Build two swarms
        let config1 = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:node1").unwrap(),
        };
        let config2 = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:node2").unwrap(),
        };

        let mut swarm1 = build_swarm(&config1).unwrap();
        let mut swarm2 = build_swarm(&config2).unwrap();

        // Listen on random TCP ports on loopback
        swarm1
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        // Pump swarm2 briefly to capture its listen address
        let mut addr2: Option<Multiaddr> = None;
        for _ in 0..20 {
            if let Ok(Some(event)) =
                tokio::time::timeout(Duration::from_millis(50), swarm2.next()).await
            {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    if address.to_string().contains("tcp") {
                        addr2 = Some(address);
                        break;
                    }
                }
            }
        }
        let addr2 = addr2.expect("swarm2 should have a listen addr");

        // Dial swarm2 from swarm1
        swarm1.dial(addr2).unwrap();

        let (cmd_tx1, cmd_rx1) = mpsc::channel(32);
        let (event_tx1, mut event_rx1) = mpsc::channel(32);
        let (cmd_tx2, cmd_rx2) = mpsc::channel(32);
        let (event_tx2, _event_rx2) = mpsc::channel(32);

        // Spawn both loops
        tokio::spawn(run_network_loop(swarm1, cmd_rx1, event_tx1));
        tokio::spawn(run_network_loop(swarm2, cmd_rx2, event_tx2));

        let handle1 = NetworkHandle::new(cmd_tx1);
        let _handle2 = NetworkHandle::new(cmd_tx2);

        // Wait for connection (up to 5 seconds)
        let discovered = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = event_rx1.recv().await {
                if matches!(event, NetworkEvent::PeerDiscovered { .. }) {
                    return true;
                }
            }
            false
        })
        .await;

        assert!(
            discovered.unwrap_or(false),
            "Node 1 should discover node 2 via direct dial"
        );

        // Verify peer count
        let count = handle1.peer_count().await.unwrap();
        assert_eq!(count, 1, "Should have exactly 1 peer");
    }

    /// mDNS discovery test — may fail in environments where multicast UDP
    /// is not available on loopback. Run manually with:
    /// `cargo test -p exo-node -- --ignored two_nodes_discover_via_mdns`
    #[tokio::test]
    #[ignore]
    async fn two_nodes_discover_via_mdns() {
        let config1 = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:mdns1").unwrap(),
        };
        let config2 = NetworkConfig {
            tcp_port: 0,
            quic_port: 0,
            seed_addrs: vec![],
            node_did: Did::new("did:exo:mdns2").unwrap(),
        };

        let mut swarm1 = build_swarm(&config1).unwrap();
        let mut swarm2 = build_swarm(&config2).unwrap();

        swarm1
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let (_cmd_tx1, cmd_rx1) = mpsc::channel(32);
        let (event_tx1, mut event_rx1) = mpsc::channel(32);
        let (_cmd_tx2, cmd_rx2) = mpsc::channel(32);
        let (event_tx2, _event_rx2) = mpsc::channel(32);

        tokio::spawn(run_network_loop(swarm1, cmd_rx1, event_tx1));
        tokio::spawn(run_network_loop(swarm2, cmd_rx2, event_tx2));

        let discovered = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = event_rx1.recv().await {
                if matches!(event, NetworkEvent::PeerDiscovered { .. }) {
                    return true;
                }
            }
            false
        })
        .await;

        assert!(discovered.unwrap_or(false), "mDNS discovery should work");
    }
}
