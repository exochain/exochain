//! Prometheus-compatible metrics exposition.
//!
//! Lightweight metrics collection and exposition in Prometheus text format.
//! Avoids heavy metric crate dependencies — uses atomic counters and gauges
//! rendered directly to the Prometheus exposition format.
//!
//! ## Exposed Metrics
//!
//! - `exochain_peer_count` — number of connected peers
//! - `exochain_consensus_round` — current consensus round
//! - `exochain_committed_height` — highest committed DAG height
//! - `exochain_dag_nodes_total` — total DAG nodes stored
//! - `exochain_validator_count` — number of validators in the set
//! - `exochain_is_validator` — whether this node is a validator (0 or 1)
//! - `exochain_uptime_seconds` — node uptime in seconds
//! - `exochain_sync_in_progress` — whether state sync is active (0 or 1)

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use exo_core::{Timestamp, hlc::HybridClock};

/// Thread-safe metrics registry for the node.
#[derive(Debug)]
pub struct NodeMetrics {
    /// Number of connected peers.
    pub peer_count: AtomicU64,
    /// Current consensus round.
    pub consensus_round: AtomicU64,
    /// Highest committed DAG height.
    pub committed_height: AtomicU64,
    /// Total DAG nodes stored.
    pub dag_nodes_total: AtomicU64,
    /// Number of validators.
    pub validator_count: AtomicU64,
    /// Whether this node is a validator.
    pub is_validator: AtomicU64,
    /// Whether state sync is in progress.
    pub sync_in_progress: AtomicU64,
    /// When the node started.
    start_time: Timestamp,
    /// HLC source used to render deterministic uptime.
    clock: Mutex<HybridClock>,
}

impl NodeMetrics {
    /// Create a new metrics registry.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_clock(HybridClock::new())
    }

    /// Create a new metrics registry with an explicit HLC source.
    #[must_use]
    pub fn new_with_clock(mut clock: HybridClock) -> Self {
        let start_time = clock.now();
        Self {
            peer_count: AtomicU64::new(0),
            consensus_round: AtomicU64::new(0),
            committed_height: AtomicU64::new(0),
            dag_nodes_total: AtomicU64::new(0),
            validator_count: AtomicU64::new(0),
            is_validator: AtomicU64::new(0),
            sync_in_progress: AtomicU64::new(0),
            start_time,
            clock: Mutex::new(clock),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        match self.clock.lock() {
            Ok(mut clock) => {
                clock
                    .now()
                    .physical_ms
                    .saturating_sub(self.start_time.physical_ms)
                    / 1000
            }
            Err(_) => {
                tracing::error!("NodeMetrics HLC mutex poisoned while rendering uptime");
                0
            }
        }
    }

    /// Render all metrics in Prometheus exposition format.
    #[must_use]
    pub fn render(&self) -> String {
        let uptime = self.uptime_seconds();

        format!(
            "# HELP exochain_peer_count Number of connected P2P peers.\n\
             # TYPE exochain_peer_count gauge\n\
             exochain_peer_count {}\n\
             \n\
             # HELP exochain_consensus_round Current BFT consensus round.\n\
             # TYPE exochain_consensus_round gauge\n\
             exochain_consensus_round {}\n\
             \n\
             # HELP exochain_committed_height Highest committed DAG height.\n\
             # TYPE exochain_committed_height gauge\n\
             exochain_committed_height {}\n\
             \n\
             # HELP exochain_dag_nodes_total Total DAG nodes stored locally.\n\
             # TYPE exochain_dag_nodes_total gauge\n\
             exochain_dag_nodes_total {}\n\
             \n\
             # HELP exochain_validator_count Number of validators in the consensus set.\n\
             # TYPE exochain_validator_count gauge\n\
             exochain_validator_count {}\n\
             \n\
             # HELP exochain_is_validator Whether this node is a consensus validator.\n\
             # TYPE exochain_is_validator gauge\n\
             exochain_is_validator {}\n\
             \n\
             # HELP exochain_uptime_seconds Node uptime in seconds.\n\
             # TYPE exochain_uptime_seconds gauge\n\
             exochain_uptime_seconds {}\n\
             \n\
             # HELP exochain_sync_in_progress Whether state sync is currently active.\n\
             # TYPE exochain_sync_in_progress gauge\n\
             exochain_sync_in_progress {}\n",
            self.peer_count.load(Ordering::Relaxed),
            self.consensus_round.load(Ordering::Relaxed),
            self.committed_height.load(Ordering::Relaxed),
            self.dag_nodes_total.load(Ordering::Relaxed),
            self.validator_count.load(Ordering::Relaxed),
            self.is_validator.load(Ordering::Relaxed),
            uptime,
            self.sync_in_progress.load(Ordering::Relaxed),
        )
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle to the node metrics.
pub type SharedMetrics = Arc<NodeMetrics>;

/// Create a new shared metrics handle.
#[must_use]
pub fn create_metrics() -> SharedMetrics {
    Arc::new(NodeMetrics::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use exo_core::hlc::HybridClock;

    use super::*;

    #[test]
    fn metrics_render_prometheus_format() {
        let metrics = NodeMetrics::new();
        metrics.peer_count.store(5, Ordering::Relaxed);
        metrics.consensus_round.store(42, Ordering::Relaxed);
        metrics.committed_height.store(100, Ordering::Relaxed);
        metrics.is_validator.store(1, Ordering::Relaxed);

        let output = metrics.render();

        assert!(output.contains("exochain_peer_count 5"));
        assert!(output.contains("exochain_consensus_round 42"));
        assert!(output.contains("exochain_committed_height 100"));
        assert!(output.contains("exochain_is_validator 1"));
        assert!(output.contains("# TYPE exochain_peer_count gauge"));
        assert!(output.contains("# HELP exochain_uptime_seconds"));
    }

    #[test]
    fn metrics_default_values() {
        let metrics = NodeMetrics::new();
        let output = metrics.render();

        assert!(output.contains("exochain_peer_count 0"));
        assert!(output.contains("exochain_consensus_round 0"));
        assert!(output.contains("exochain_committed_height 0"));
        assert!(output.contains("exochain_is_validator 0"));
    }

    #[test]
    fn metrics_uptime_uses_injected_hlc_source() {
        let wall = Arc::new(AtomicU64::new(42_000));
        let wall_for_clock = Arc::clone(&wall);
        let metrics = NodeMetrics::new_with_clock(HybridClock::with_wall_clock(move || {
            wall_for_clock.load(Ordering::Relaxed)
        }));

        wall.store(45_000, Ordering::Relaxed);
        let output = metrics.render();

        assert!(output.contains("exochain_uptime_seconds 3"));
    }

    #[test]
    fn metrics_atomic_updates() {
        let metrics = Arc::new(NodeMetrics::new());

        metrics.peer_count.store(10, Ordering::Relaxed);
        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 10);

        metrics.peer_count.fetch_add(5, Ordering::Relaxed);
        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 15);
    }

    #[test]
    fn shared_metrics_thread_safe() {
        let metrics = create_metrics();
        let m2 = Arc::clone(&metrics);

        std::thread::spawn(move || {
            m2.peer_count.store(42, Ordering::Relaxed);
        })
        .join()
        .unwrap();

        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn default_runtime_sources_do_not_read_wall_clock_directly() {
        let metrics_source = include_str!("metrics.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("metrics tests marker present");
        let sentinels_source = include_str!("sentinels.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("sentinels tests marker present");

        assert!(!metrics_source.contains("Instant::now"));
        assert!(!metrics_source.contains("time::Instant"));
        assert!(!sentinels_source.contains("SystemTime::now"));
    }
}
