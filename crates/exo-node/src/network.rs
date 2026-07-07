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

//! P2P networking layer — libp2p swarm with gossipsub, Kademlia, and identify.
//!
//! This module bridges the existing `exo-api::p2p` abstractions (PeerRegistry,
//! ASN diversity, rate limiting) with a real libp2p transport layer.

#![allow(clippy::large_enum_variant, clippy::collapsible_match)]

use std::time::Duration;

use exo_api::p2p::{PeerId as ExoPeerId, PeerInfo, PeerRegistry, RateLimiter};
use exo_core::{
    hash::hash_structured,
    types::{Did, Hash256, Timestamp},
};
use futures::StreamExt;
use libp2p_core::{
    Multiaddr, Transport,
    muxing::StreamMuxerBox,
    transport::{Boxed, timeout::TransportTimeout},
    upgrade,
};
use libp2p_gossipsub as gossipsub;
use libp2p_identify as identify;
use libp2p_identity::{Keypair, PeerId};
use libp2p_kad as kad;
use libp2p_noise as noise;
use libp2p_ping as ping;
use libp2p_quic as quic;
use libp2p_swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p_tcp as tcp;
use libp2p_yamux as yamux;
use tokio::sync::mpsc;

use crate::wire::{self, WireMessage, topics};

const GOSSIPSUB_MESSAGE_ID_DOMAIN: &str = "exo.node.gossipsub.message-id.v1";
const IDENTIFY_AGENT_VERSION: &str = "exochain/1.0";
pub(crate) const NETWORK_PUBLISH_MAX_ATTEMPTS: usize = 3;
const NETWORK_PUBLISH_RETRY_BACKOFF_MS: u64 = 50;
const NETWORK_PUBLISH_ACK_TIMEOUT_MS: u64 = 5_000;
const P2P_RATE_LIMIT_WINDOW_SECS: u64 = 60;

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
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
pub struct ExochainBehaviour {
    /// Pub/sub for consensus and governance broadcasts.
    pub gossipsub: gossipsub::Behaviour,
    /// Distributed hash table for peer discovery.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
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
    Publish {
        topic: String,
        message: WireMessage,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
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
}

/// Build the libp2p swarm with all behaviours composed.
pub fn build_swarm() -> anyhow::Result<Swarm<ExochainBehaviour>> {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let transport = build_transport(&keypair)?;
    let behaviour = build_behaviour(&keypair, peer_id)?;
    let swarm_config = libp2p_swarm::Config::with_tokio_executor()
        .with_idle_connection_timeout(Duration::from_secs(120));
    let swarm = Swarm::new(
        TransportTimeout::new(transport, Duration::from_secs(10)).boxed(),
        behaviour,
        peer_id,
        swarm_config,
    );

    Ok(swarm)
}

fn build_transport(keypair: &Keypair) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(keypair)?)
        .multiplex(yamux::Config::default())
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));

    let quic_transport = quic::tokio::Transport::new(quic::Config::new(keypair))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));

    Ok(tcp_transport
        .or_transport(quic_transport)
        .map(|transport, _| transport.into_inner())
        .boxed())
}

fn build_behaviour(keypair: &Keypair, peer_id: PeerId) -> anyhow::Result<ExochainBehaviour> {
    let message_id_fn = canonical_gossipsub_message_id;
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .max_transmit_size(wire::MAX_WIRE_MESSAGE_BYTES)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|e| std::io::Error::other(format!("gossipsub config: {e}")))?;

    let mut gossipsub_behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| std::io::Error::other(format!("gossipsub: {e}")))?;

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

    let kademlia = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
    let identify = identify::Behaviour::new(
        identify::Config::new("/exochain/1.0.0".into(), keypair.public())
            .with_agent_version(IDENTIFY_AGENT_VERSION.into())
            .with_push_listen_addr_updates(true),
    );
    let ping = ping::Behaviour::default();

    Ok(ExochainBehaviour {
        gossipsub: gossipsub_behaviour,
        kademlia,
        identify,
        ping,
    })
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
/// 2. Bridges identified peer addresses to Kademlia
/// 3. Forwards received gossipsub messages as `NetworkEvent`s
/// 4. Handles `NetworkCommand`s from the application layer
pub async fn run_network_loop(
    mut swarm: Swarm<ExochainBehaviour>,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
) {
    let mut peer_registry = PeerRegistry::new();
    let mut rate_limiter = RateLimiter::new();
    let mut rate_limit_window =
        tokio::time::interval(Duration::from_secs(P2P_RATE_LIMIT_WINDOW_SECS));
    rate_limit_window.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    rate_limit_window.tick().await;

    loop {
        tokio::select! {
            _ = rate_limit_window.tick() => {
                rate_limiter.reset();
                tracing::debug!("P2P rate-limit window reset");
            }

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
                        let exo_peer = match libp2p_peer_to_exo(&propagation_source) {
                            Ok(exo_peer) => exo_peer,
                            Err(e) => {
                                tracing::warn!(
                                    peer = %propagation_source,
                                    err = %e,
                                    "Failed to derive exochain peer ID; dropping message"
                                );
                                continue;
                            }
                        };

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
                    NetworkCommand::Publish { topic, message, reply } => {
                        let result = match wire::encode(&message) {
                            Ok(bytes) => {
                                let topic = gossipsub::IdentTopic::new(topic);
                                match swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                    Ok(msg_id) => {
                                        tracing::debug!(%msg_id, "Published message");
                                        Ok(())
                                    }
                                    Err(e) => {
                                        let reason = format!("gossipsub publish failed: {e}");
                                        tracing::warn!(err = %reason, "Failed to publish");
                                        Err(reason)
                                    }
                                }
                            }
                            Err(e) => {
                                let reason = format!("wire encode failed: {e}");
                                tracing::warn!(err = %reason, "Failed to encode message");
                                Err(reason)
                            }
                        };
                        if reply.send(result).is_err() {
                            tracing::warn!("Network publish reply receiver dropped");
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
fn libp2p_peer_to_exo(peer_id: &PeerId) -> Result<ExoPeerId, String> {
    let did_str = format!("did:exo:peer-{}", peer_id);
    match Did::new(&did_str) {
        Ok(did) => Ok(ExoPeerId(did)),
        Err(primary_error) => {
            // Fallback: use the hash of the peer ID.
            let hash = blake3::hash(peer_id.to_bytes().as_slice());
            let fallback_did = format!("did:exo:peer-{}", hex::encode(&hash.as_bytes()[..16]));
            Did::new(&fallback_did)
                .map(ExoPeerId)
                .map_err(|fallback_error| {
                    format!(
                        "primary peer DID rejected ({primary_error}); fallback peer DID \
                     {fallback_did} rejected ({fallback_error})"
                    )
                })
        }
    }
}

/// Register a libp2p peer in the exochain PeerRegistry.
fn register_peer(registry: &mut PeerRegistry, peer_id: &PeerId) {
    let exo_peer = match libp2p_peer_to_exo(peer_id) {
        Ok(exo_peer) => exo_peer,
        Err(e) => {
            tracing::warn!(
                peer = %peer_id,
                err = %e,
                "Failed to derive exochain peer ID; skipping peer registry update"
            );
            return;
        }
    };
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
        let mut last_error = None;
        for attempt in 1..=NETWORK_PUBLISH_MAX_ATTEMPTS {
            match self.publish_once(topic, message.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_error = Some(err);
                    if attempt < NETWORK_PUBLISH_MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(NETWORK_PUBLISH_RETRY_BACKOFF_MS))
                            .await;
                    }
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("publish failed without a recorded error")))
    }

    async fn publish_once(&self, topic: &str, message: WireMessage) -> anyhow::Result<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Publish {
                topic: topic.to_string(),
                message,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Network task has stopped"))?;

        tokio::time::timeout(
            Duration::from_millis(NETWORK_PUBLISH_ACK_TIMEOUT_MS),
            reply_rx,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Network publish acknowledgement timed out"))?
        .map_err(|_| anyhow::anyhow!("Network task dropped publish acknowledgement"))?
        .map_err(|err| anyhow::anyhow!(err))
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use libp2p_core::multiaddr::Protocol;

    use super::*;

    #[test]
    fn libp2p_peer_to_exo_deterministic() {
        let peer_id = PeerId::random();
        let exo1 = libp2p_peer_to_exo(&peer_id).unwrap();
        let exo2 = libp2p_peer_to_exo(&peer_id).unwrap();
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
        let swarm = build_swarm();
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
    fn production_gossipsub_config_caps_wire_message_bytes() {
        let source = include_str!("network.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source section exists");
        assert!(
            production.contains(".max_transmit_size(wire::MAX_WIRE_MESSAGE_BYTES)"),
            "gossipsub must reject oversized wire frames before normal message handling"
        );
    }

    #[test]
    fn production_network_loop_resets_rate_limiter_window() {
        let source = include_str!("network.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source section exists");
        let loop_source = production
            .split("pub async fn run_network_loop")
            .nth(1)
            .expect("network loop source exists")
            .split("impl NetworkHandle")
            .next()
            .expect("network handle source follows loop");

        assert!(
            production.contains("P2P_RATE_LIMIT_WINDOW_SECS"),
            "network rate limiter must declare a bounded reset window"
        );
        assert!(
            loop_source.contains("let mut rate_limit_window"),
            "network loop must keep a rate-limit window timer"
        );
        assert!(
            loop_source.contains("rate_limit_window.tick().await"),
            "network loop must consume the immediate interval tick before handling traffic"
        );
        assert!(
            loop_source.contains("_ = rate_limit_window.tick()"),
            "network loop must poll the rate-limit reset window"
        );
        assert!(
            loop_source.contains("rate_limiter.reset()"),
            "network loop must reset rate-limit state when the window rotates"
        );
        assert!(
            loop_source.find("let mut rate_limiter = RateLimiter::new()")
                < loop_source.find("rate_limiter.reset()"),
            "rate limiter must be initialized before its periodic reset"
        );
    }

    #[test]
    fn production_network_code_does_not_suppress_expect_lint() {
        let source = include_str!("network.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source section exists");

        assert!(
            !production.contains("clippy::expect_used"),
            "expect_used must not be allowed across network-facing production code"
        );
        assert!(
            !production.contains(".expect("),
            "network-facing production code must not rely on panic-prone expect calls"
        );
    }

    #[test]
    fn identify_agent_version_does_not_broadcast_node_did() {
        let source = include_str!("network.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source section exists");

        assert!(
            !production.contains("node_did_for_identify"),
            "libp2p identify metadata must not include the node DID"
        );
        assert!(
            !production.contains("with_agent_version(format!"),
            "libp2p identify agent version must be static, not DID-derived"
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
        let swarm = build_swarm().unwrap();

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = mpsc::channel(32);

        let handle = NetworkHandle::new(cmd_tx);

        // Spawn network loop
        tokio::spawn(run_network_loop(swarm, cmd_rx, event_tx));

        // Query peer count before listening so concurrent network tests cannot
        // connect through loopback and make this assertion nondeterministic.
        let count = handle.peer_count().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn network_handle_publish_reports_gossipsub_failure() {
        let swarm = build_swarm().unwrap();

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = mpsc::channel(32);

        let handle = NetworkHandle::new(cmd_tx);
        tokio::spawn(run_network_loop(swarm, cmd_rx, event_tx));

        let oversized_msg = WireMessage::GovernanceEvent(wire::GovernanceEventMsg {
            sender: Did::new("did:exo:network-publisher").unwrap(),
            event_type: wire::GovernanceEventType::AuditEntry,
            payload: vec![0; wire::MAX_WIRE_MESSAGE_BYTES + 1],
            timestamp: Timestamp::ZERO,
            signature: exo_core::types::Signature::empty(),
        });

        let result = handle.publish(topics::GOVERNANCE, oversized_msg).await;

        assert!(
            result.is_err(),
            "publish must return the network-layer failure instead of only confirming queueing"
        );
    }

    #[tokio::test]
    async fn network_handle_publish_retries_until_acknowledged() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let handle = NetworkHandle::new(cmd_tx);
        let publish_task = tokio::spawn(async move {
            let message = WireMessage::PeerExchange(wire::PeerExchangeMsg {
                sender: Did::new("did:exo:network-retry").unwrap(),
                peers: Vec::new(),
            });
            handle.publish(topics::PEER_EXCHANGE, message).await
        });

        for attempt in 1..=2 {
            let command = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
                .await
                .expect("publish command should arrive before timeout")
                .expect("publish command should be sent");
            let NetworkCommand::Publish { topic, reply, .. } = command else {
                panic!("expected publish command");
            };
            assert_eq!(topic, topics::PEER_EXCHANGE);
            if attempt == 1 {
                reply
                    .send(Err("transient publish failure".into()))
                    .expect("first publish attempt should be waiting");
            } else {
                reply
                    .send(Ok(()))
                    .expect("second publish attempt should be waiting");
            }
        }

        publish_task
            .await
            .expect("publish task joins")
            .expect("publish succeeds after retry");
    }

    async fn wait_for_tcp_listen_addr(swarm: &mut Swarm<ExochainBehaviour>) -> Multiaddr {
        for _ in 0..100 {
            if let Ok(Some(SwarmEvent::NewListenAddr { address, .. })) =
                tokio::time::timeout(Duration::from_millis(50), swarm.next()).await
            {
                if address
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
                {
                    return address;
                }
            }
        }

        panic!("swarm should have a TCP listen address");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_connect_via_dial() {
        let swarm1 = build_swarm().unwrap();
        let mut swarm2 = build_swarm().unwrap();
        let peer2 = *swarm2.local_peer_id();

        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let mut addr2 = wait_for_tcp_listen_addr(&mut swarm2).await;
        addr2.push(Protocol::P2p(peer2));

        let (cmd_tx1, cmd_rx1) = mpsc::channel(32);
        let (event_tx1, mut event_rx1) = mpsc::channel(32);
        let (cmd_tx2, cmd_rx2) = mpsc::channel(32);
        let (event_tx2, _event_rx2) = mpsc::channel(32);

        // Spawn both loops
        tokio::spawn(run_network_loop(swarm1, cmd_rx1, event_tx1));
        tokio::spawn(run_network_loop(swarm2, cmd_rx2, event_tx2));

        let handle1 = NetworkHandle::new(cmd_tx1);
        let _handle2 = NetworkHandle::new(cmd_tx2);

        handle1.dial(addr2).await.unwrap();

        // Wait for connection under full-suite scheduler load.
        let discovered = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = event_rx1.recv().await {
                if matches!(event, NetworkEvent::PeerDiscovered { peer_id } if peer_id == peer2) {
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
        let count = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let count = handle1.peer_count().await.unwrap();
                if count == 1 {
                    return count;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or(0);
        assert_eq!(count, 1, "Should have exactly 1 peer");
    }

    // -----------------------------------------------------------------
    // VCG-012 RED — distributed HLC sync (D6: HLC rides the existing
    // gossipsub DAG-sync channel; no dedicated clock topic).
    // -----------------------------------------------------------------

    /// RED (expected compile failure until D6 lands): there is no
    /// `WireMessage` variant carrying an HLC `Timestamp` today. D6 requires
    /// HLC timestamps to piggyback on the existing gossipsub DAG-sync
    /// channel (`topics::CONSENSUS`) rather than adding a dedicated clock
    /// topic. This test performs a REAL two-node wire round trip: node A
    /// publishes an HLC-carrying wire message over gossipsub, node B
    /// receives it via its real `NetworkEvent::MessageReceived` stream and
    /// must call `HybridClock::update` on receipt, advancing its local
    /// clock past the received remote timestamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hlc_timestamp_round_trips_over_gossipsub() {
        let mut swarm1 = build_swarm().unwrap();
        let mut swarm2 = build_swarm().unwrap();
        let peer2 = *swarm2.local_peer_id();

        swarm1
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let mut addr2 = wait_for_tcp_listen_addr(&mut swarm2).await;
        addr2.push(Protocol::P2p(peer2));

        let (cmd_tx1, cmd_rx1) = mpsc::channel(32);
        let (event_tx1, _event_rx1) = mpsc::channel(32);
        // Node B is a pure receiver in this round-trip; its command sender is
        // never used to publish, but must stay bound (underscore, not dropped)
        // so node B's network loop keeps a live command channel for its
        // lifetime.
        let (_cmd_tx2, cmd_rx2) = mpsc::channel(32);
        let (event_tx2, mut event_rx2) = mpsc::channel(32);

        tokio::spawn(run_network_loop(swarm1, cmd_rx1, event_tx1));
        tokio::spawn(run_network_loop(swarm2, cmd_rx2, event_tx2));

        let handle1 = NetworkHandle::new(cmd_tx1);

        handle1.dial(addr2).await.unwrap();

        // Wait for the gossipsub mesh to form on the existing DAG-sync
        // (consensus) topic before publishing — no dedicated clock topic.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // A *legitimately fresh* remote HLC timestamp: node B's physical clock
        // sits at a realistic base and node A's timestamp is only 100 ms ahead
        // — well inside HybridClock's 5 s drift tolerance. This is the
        // happy-path round trip: a fresh remote reading is received over the
        // wire and merged. The pathological "far-future" timestamp that must
        // be rejected-and-recorded is the domain of
        // clock_anomaly_emits_dag_evidence_object, not this test.
        let node_b_physical_ms: u64 = 1_000_000;
        let remote_timestamp = Timestamp::new(node_b_physical_ms + 100, 3);

        // HLC rides the existing DAG-sync (consensus) gossipsub channel per
        // D6 — it does not get a dedicated clock topic.
        let hlc_keypair = exo_core::crypto::KeyPair::from_secret_bytes([42u8; 32]).unwrap();
        let hlc_sender = crate::identity::did_from_public_key(hlc_keypair.public_key()).unwrap();
        let hlc_payload = wire::HlcSyncMsg::signing_payload(
            &hlc_sender,
            &remote_timestamp,
            hlc_keypair.public_key(),
        )
        .unwrap();
        let hlc_message = WireMessage::HlcSync(wire::HlcSyncMsg {
            sender: hlc_sender,
            timestamp: remote_timestamp,
            public_key: *hlc_keypair.public_key(),
            signature: hlc_keypair.sign(&hlc_payload),
        });

        handle1
            .publish(topics::CONSENSUS, hlc_message)
            .await
            .expect("HLC wire message should publish over the existing DAG-sync channel");

        let mut node_b_clock =
            exo_core::hlc::HybridClock::with_wall_clock(move || node_b_physical_ms);

        let advanced = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = event_rx2.recv().await {
                if let NetworkEvent::MessageReceived { message, .. } = event {
                    if let WireMessage::HlcSync(hlc) = message {
                        node_b_clock
                            .update(&hlc.timestamp)
                            .expect("HLC update should accept a fresh remote timestamp");
                        return true;
                    }
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        assert!(
            advanced,
            "node B should receive the HLC wire message over gossipsub and call HybridClock::update"
        );
        assert!(
            node_b_clock.current() > remote_timestamp,
            "node B's HybridClock must advance strictly past the received remote HLC timestamp"
        );
    }

    /// RED (expected behavioral failure until D6 lands): D6 requires that
    /// any drift/replay anomaly detected during HLC sync is recorded as a
    /// DAG evidence object (a constitutional event), not merely logged.
    /// This test simulates a replay/drift anomaly arriving over the wire
    /// and asserts a retrievable evidence object was recorded.
    #[tokio::test]
    async fn clock_anomaly_emits_dag_evidence_object() {
        // No such recorder exists yet on the exo-node side — compile-red.
        let recorder = crate::sync::HlcAnomalyRecorder::new();

        let mut clock = exo_core::hlc::HybridClock::with_wall_clock(|| 1_000);
        let excessive_drift = Timestamp::new(1_000 + clock.max_drift_ms() + 1, 0);

        let outcome =
            crate::sync::observe_remote_hlc_timestamp(&mut clock, &excessive_drift, &recorder);

        assert!(
            outcome.is_err(),
            "excessive drift must still fail closed at the clock layer"
        );

        let recorded = recorder.recorded_evidence();
        assert_eq!(
            recorded.len(),
            1,
            "a clock drift anomaly must record exactly one DAG evidence object, not just a log line"
        );
        assert_eq!(recorded[0].anomaly_physical_ms, excessive_drift.physical_ms);
    }
}
