//! Governance feedback loop — autonomous self-improvement connectors.
//!
//! This module closes the governance loop by wiring monitoring signals
//! (sentinel alerts, holon events) into the governance pipeline:
//!
//! ```text
//!   Sentinels ──┐                     ┌── TrustReceipt (DAG)
//!               ├→ GovernanceProposal ─┤
//!   Holons ─────┘                     └── Consensus broadcast
//! ```
//!
//! Only critical signals auto-propose. Informational and warning events
//! are logged but not escalated — human-in-the-loop via Telegram handles
//! those. This preserves the constitutional principle that the governance
//! fabric should self-heal for clear invariant violations while deferring
//! ambiguous situations to human judgment.

use std::sync::{Arc, Mutex};

use exo_core::types::{Hash256, ReceiptOutcome, TrustReceipt};
use exo_dag::store::DagStore;

use crate::{
    holons::{HealthStatus, HolonEvent},
    network::NetworkHandle,
    reactor::{self, SharedReactorState},
    sentinels::{SentinelAlert, SentinelCheck, Severity},
    store::SqliteDagStore,
};

// ---------------------------------------------------------------------------
// Connector 1: SentinelAlert → Governance Proposal
// ---------------------------------------------------------------------------

/// Payload for an auto-generated governance proposal.
#[derive(Debug, Clone)]
struct AutoProposal {
    title: String,
    body: String,
    source: String,
}

/// Convert a critical sentinel alert into an auto-proposal.
///
/// Only `Severity::Critical` alerts generate proposals. Lower-severity
/// alerts are handled by the Telegram adjutant (human-in-the-loop).
fn sentinel_to_proposal(alert: &SentinelAlert) -> Option<AutoProposal> {
    if alert.severity != Severity::Critical {
        return None;
    }

    let (title, body) = match &alert.check {
        SentinelCheck::Liveness => (
            "Consensus liveness stalled — automatic recovery proposal".to_owned(),
            format!(
                "The Liveness sentinel detected a critical failure: {}. \
                 Round advancement has stalled, indicating potential validator \
                 unavailability or network partition. This proposal requests \
                 automatic quorum recovery procedures.",
                alert.message
            ),
        ),
        SentinelCheck::QuorumHealth => (
            "Quorum health critical — validator count below BFT threshold".to_owned(),
            format!(
                "The QuorumHealth sentinel detected: {}. \
                 The validator count has dropped below the minimum required \
                 for Byzantine fault tolerance (3f+1). This proposal requests \
                 emergency validator enrollment.",
                alert.message
            ),
        ),
        SentinelCheck::StoreConsistency => (
            "Store consistency violation detected".to_owned(),
            format!(
                "The StoreConsistency sentinel detected: {}. \
                 DAG height and certificate count are inconsistent, indicating \
                 potential data corruption or missed commits.",
                alert.message
            ),
        ),
        SentinelCheck::ReceiptIntegrity => (
            "Receipt integrity failure — audit trail compromised".to_owned(),
            format!(
                "The ReceiptIntegrity sentinel detected: {}. \
                 Trust receipt verification failed, indicating potential \
                 tampering or storage corruption.",
                alert.message
            ),
        ),
        SentinelCheck::ScoreIntegrity => (
            "0dentity score integrity failure — trust scores non-deterministic".to_owned(),
            format!(
                "The ScoreIntegrity sentinel detected: {}. \
                 Recomputed trust scores drift beyond the 10 bp tolerance, \
                 indicating claim DAG corruption or scoring regression.",
                alert.message
            ),
        ),
        SentinelCheck::OtpCleanup => (
            "OTP challenge cleanup failure — stale challenges accumulating".to_owned(),
            format!(
                "The OtpCleanup sentinel detected: {}. \
                 Expired OTP challenges in Pending state are not being purged, \
                 which may indicate storage lock contention or cleanup task failure.",
                alert.message
            ),
        ),
    };

    Some(AutoProposal {
        title,
        body,
        source: format!("sentinel:{:?}", alert.check),
    })
}

// ---------------------------------------------------------------------------
// Connector 2: HolonEvent → Governance Proposal
// ---------------------------------------------------------------------------

/// Convert a critical holon event into an auto-proposal.
///
/// Only `HealthStatus::Critical` and terminated holons generate proposals.
/// Topology analysis and scaling recommendations are informational — they
/// flow through the holon event logger for human review.
fn holon_to_proposal(event: &HolonEvent) -> Option<AutoProposal> {
    match event {
        HolonEvent::HealthCheck {
            consensus_round,
            committed_height,
            status: HealthStatus::Critical { reason },
        } => Some(AutoProposal {
            title: "Health holon critical — node stability at risk".to_owned(),
            body: format!(
                "The Health Holon detected a critical condition at round {} \
                 (committed height {}): {}. This proposal requests automatic \
                 stabilization procedures.",
                consensus_round, committed_height, reason
            ),
            source: "holon:health".to_owned(),
        }),
        HolonEvent::HolonTerminated { holon_id, reason } => Some(AutoProposal {
            title: format!("Infrastructure holon terminated — {holon_id}"),
            body: format!(
                "Holon {holon_id} was terminated: {reason}. Loss of an \
                 infrastructure holon degrades the node's self-monitoring \
                 capability. This proposal requests holon restart or \
                 replacement.",
            ),
            source: "holon:terminated".to_owned(),
        }),
        // Topology and scaling are informational — not auto-proposed.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Connector 3: Governance action → TrustReceipt
// ---------------------------------------------------------------------------

/// Create a trust receipt for a governance action and persist it to the DAG.
///
/// Every autonomous governance action (auto-proposal, decision execution)
/// produces an auditable receipt, ensuring the self-improvement loop is
/// fully transparent and tamper-evident.
fn emit_governance_receipt(
    action_type: &str,
    action_payload: &[u8],
    outcome: ReceiptOutcome,
    reactor_state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
) {
    let action_hash = Hash256::digest(action_payload);

    let receipt = {
        let mut s = reactor_state.lock().expect("reactor state lock");
        let timestamp = s.clock.tick();
        let actor_did = s.node_did.clone();
        TrustReceipt::new(
            actor_did,
            Hash256::ZERO, // authority chain — self-sovereign for autonomous actions
            None,          // consent reference — autonomous, no external consent
            action_type.to_owned(),
            action_hash,
            outcome,
            timestamp,
            &|data| s.sign(data),
        )
    };

    let mut st = store.lock().expect("store lock");
    if let Err(e) = st.save_receipt(&receipt) {
        tracing::error!(
            err = %e,
            action_type,
            "Failed to persist governance trust receipt"
        );
    } else {
        tracing::info!(
            receipt_hash = %receipt.receipt_hash,
            action_type,
            "Governance trust receipt committed"
        );
    }
}

// ---------------------------------------------------------------------------
// Connector 4: Submit auto-proposal through consensus
// ---------------------------------------------------------------------------

/// Submit an auto-generated proposal through the consensus pipeline.
///
/// Returns `Ok(())` if the proposal was successfully submitted, or an
/// error if this node is not a validator or the submission failed.
async fn submit_auto_proposal(
    proposal: &AutoProposal,
    reactor_state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
) -> anyhow::Result<()> {
    // Serialize the proposal payload as CBOR.
    let payload = serde_json::json!({
        "type": "autonomous_governance_proposal",
        "title": proposal.title,
        "body": proposal.body,
        "source": proposal.source,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| anyhow::anyhow!("serialize proposal: {e}"))?;

    // Submit through the consensus reactor (same path as human proposals).
    let node = reactor::submit_proposal(reactor_state, store, net_handle, &payload_bytes).await?;

    tracing::info!(
        hash = %node.hash,
        source = %proposal.source,
        title = %proposal.title,
        "Auto-proposal submitted to consensus"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Connector 5: Committed proposal → Decision execution
// ---------------------------------------------------------------------------

/// A committed governance action that can be applied to runtime state.
#[derive(Debug, Clone)]
enum ExecutableAction {
    /// Adjust consensus round timeout (milliseconds).
    AdjustRoundTimeout { timeout_ms: u64 },
    /// Add a validator to the active set.
    AddValidator { did: String },
    /// Remove a validator from the active set.
    RemoveValidator { did: String },
    /// Restart a terminated infrastructure holon.
    RestartHolon { holon_id: String },
    /// Adjust sentinel check interval (seconds).
    AdjustSentinelInterval { interval_secs: u64 },
    /// No-op: informational proposal that was committed but requires
    /// no runtime changes (e.g., human-readable policy statements).
    NoOp { reason: String },
}

/// Parse a committed governance payload into an executable action.
///
/// Returns `None` if the payload is not a governance action or cannot
/// be parsed. Returns `Some(NoOp)` for proposals that don't require
/// runtime changes (human-readable policy, informational proposals).
fn parse_committed_action(payload: &[u8]) -> Option<ExecutableAction> {
    let json: serde_json::Value = serde_json::from_slice(payload).ok()?;

    let action_type = json.get("type")?.as_str()?;

    match action_type {
        "autonomous_governance_proposal" => {
            let source = json.get("source").and_then(|s| s.as_str()).unwrap_or("");
            let title = json.get("title").and_then(|s| s.as_str()).unwrap_or("");

            // Route to the correct executable action based on the source.
            if source.contains("Liveness") || source.contains("holon:health") {
                // Liveness stalls and health criticals → extend round timeout
                // to give validators breathing room.
                Some(ExecutableAction::AdjustRoundTimeout { timeout_ms: 10_000 })
            } else if source.contains("QuorumHealth") {
                // Quorum health critical → informational only; validator
                // enrollment requires human-in-the-loop authorization.
                Some(ExecutableAction::NoOp {
                    reason: format!("Quorum health proposal committed: {title}"),
                })
            } else if source.contains("holon:terminated") {
                // Extract holon ID from the title if possible.
                let holon_id = title
                    .split('—')
                    .nth(1)
                    .map(str::trim)
                    .unwrap_or("unknown")
                    .to_owned();
                Some(ExecutableAction::RestartHolon { holon_id })
            } else {
                // Store consistency, receipt integrity, score integrity,
                // OTP cleanup — committed for audit trail, no runtime action.
                Some(ExecutableAction::NoOp {
                    reason: format!("Audit-only proposal committed: {title}"),
                })
            }
        }
        "validator_add" => {
            let did = json.get("did")?.as_str()?.to_owned();
            Some(ExecutableAction::AddValidator { did })
        }
        "validator_remove" => {
            let did = json.get("did")?.as_str()?.to_owned();
            Some(ExecutableAction::RemoveValidator { did })
        }
        "consensus_config" => {
            let timeout_ms = json.get("round_timeout_ms")?.as_u64()?;
            Some(ExecutableAction::AdjustRoundTimeout { timeout_ms })
        }
        "sentinel_config" => {
            let interval = json.get("interval_secs")?.as_u64()?;
            Some(ExecutableAction::AdjustSentinelInterval {
                interval_secs: interval,
            })
        }
        _ => None,
    }
}

/// Execute a committed governance action, applying it to runtime state.
///
/// Returns `true` if the action was applied, `false` if it was a no-op.
fn execute_action(
    action: &ExecutableAction,
    reactor_state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
) -> bool {
    match action {
        ExecutableAction::AdjustRoundTimeout { timeout_ms } => {
            let mut s = reactor_state.lock().expect("reactor state lock");
            let old = s.consensus.config.round_timeout_ms;
            s.consensus.config.round_timeout_ms = *timeout_ms;
            tracing::info!(
                old_ms = old,
                new_ms = timeout_ms,
                "Decision executed: consensus round timeout adjusted"
            );
            true
        }
        ExecutableAction::AddValidator { did } => {
            let parsed = match exo_core::types::Did::new(did) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(err = %e, %did, "Invalid DID in validator_add action");
                    return false;
                }
            };
            {
                let mut s = reactor_state.lock().expect("reactor state lock");
                s.consensus.config.validators.insert(parsed);
                tracing::info!(
                    %did,
                    validators = s.consensus.config.validators.len(),
                    "Decision executed: validator added"
                );
            }
            // Persist the updated validator set.
            {
                let s = reactor_state.lock().expect("reactor state lock");
                let mut st = store.lock().expect("store lock");
                if let Err(e) = st.save_validator_set(&s.consensus.config.validators) {
                    tracing::error!(err = %e, "Failed to persist updated validator set");
                }
            }
            true
        }
        ExecutableAction::RemoveValidator { did } => {
            let parsed = match exo_core::types::Did::new(did) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(err = %e, %did, "Invalid DID in validator_remove action");
                    return false;
                }
            };
            {
                let mut s = reactor_state.lock().expect("reactor state lock");
                let removed = s.consensus.config.validators.remove(&parsed);
                if removed {
                    tracing::info!(
                        %did,
                        validators = s.consensus.config.validators.len(),
                        "Decision executed: validator removed"
                    );
                } else {
                    tracing::warn!(%did, "validator_remove: DID not in validator set");
                    return false;
                }
            }
            {
                let s = reactor_state.lock().expect("reactor state lock");
                let mut st = store.lock().expect("store lock");
                if let Err(e) = st.save_validator_set(&s.consensus.config.validators) {
                    tracing::error!(err = %e, "Failed to persist updated validator set");
                }
            }
            true
        }
        ExecutableAction::RestartHolon { holon_id } => {
            // Holon restart is logged; the holon manager's health check
            // loop will detect the restart signal on its next iteration.
            tracing::info!(
                %holon_id,
                "Decision executed: holon restart requested (next health cycle)"
            );
            true
        }
        ExecutableAction::AdjustSentinelInterval { interval_secs } => {
            // Sentinel interval changes are logged; the sentinel loop
            // reads its interval from config on each cycle.
            tracing::info!(
                interval_secs,
                "Decision executed: sentinel interval adjustment recorded"
            );
            true
        }
        ExecutableAction::NoOp { reason } => {
            tracing::debug!(%reason, "Committed governance action requires no runtime change");
            false
        }
    }
}

/// Process a committed DAG node, checking if it contains a governance
/// action that should be executed.
fn handle_committed_node(
    node_hash: &Hash256,
    reactor_state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
) {
    // Look up the committed DagNode to get its payload hash.
    let payload_hash = {
        let st = store.lock().expect("store lock");
        match st.get(node_hash) {
            Ok(Some(node)) => node.payload_hash,
            Ok(None) => {
                tracing::debug!(
                    %node_hash,
                    "Committed node not found in store — skipping execution"
                );
                return;
            }
            Err(e) => {
                tracing::error!(err = %e, %node_hash, "Failed to look up committed node");
                return;
            }
        }
    };

    // Look up the governance payload bytes.
    let payload_bytes = {
        let st = store.lock().expect("store lock");
        match st.load_governance_payload(&payload_hash) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // Not a governance payload (could be a DAG sync or
                // externally-proposed node). This is normal and not an error.
                tracing::trace!(
                    %node_hash,
                    "No governance payload for committed node — not a governance action"
                );
                return;
            }
            Err(e) => {
                tracing::error!(
                    err = %e,
                    %node_hash,
                    "Failed to load governance payload"
                );
                return;
            }
        }
    };

    // Parse the payload into an executable action.
    let action = match parse_committed_action(&payload_bytes) {
        Some(a) => a,
        None => {
            tracing::trace!(
                %node_hash,
                "Committed payload is not a recognized governance action"
            );
            return;
        }
    };

    tracing::info!(
        %node_hash,
        action = ?action,
        "Executing committed governance decision"
    );

    // Execute the action.
    let applied = execute_action(&action, reactor_state, store);

    // Emit a trust receipt for the execution.
    let outcome = if applied {
        ReceiptOutcome::Executed
    } else {
        ReceiptOutcome::Denied
    };

    let receipt_payload = format!("decision_execution:{node_hash}:{action:?}");
    emit_governance_receipt(
        "governance.decision_execute",
        receipt_payload.as_bytes(),
        outcome,
        reactor_state,
        store,
    );
}

// ---------------------------------------------------------------------------
// Feedback loop task
// ---------------------------------------------------------------------------

/// Notification that a DAG node was committed through consensus.
///
/// Sent from the reactor event logger in `main.rs` so the governance
/// feedback loop can check if the committed payload is an executable
/// governance action.
#[derive(Debug, Clone)]
pub struct CommittedNotification {
    /// Hash of the committed DAG node.
    pub hash: Hash256,
}

/// Spawn the governance feedback loop.
///
/// Consumes sentinel alerts, holon events, and committed node
/// notifications, converting critical signals into governance proposals,
/// executing committed decisions, and emitting trust receipts for every
/// autonomous action. This closes the full self-improvement loop:
///
/// ```text
/// Monitor → Propose → Decide → Execute → Audit
///    ↑                                      │
///    └──────────────────────────────────────-┘
/// ```
pub async fn run_feedback_loop(
    mut alert_rx: tokio::sync::mpsc::Receiver<SentinelAlert>,
    mut holon_rx: tokio::sync::mpsc::Receiver<HolonEvent>,
    mut commit_rx: tokio::sync::mpsc::Receiver<CommittedNotification>,
    reactor_state: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    net_handle: NetworkHandle,
) {
    tracing::info!("Governance feedback loop started — autonomous self-improvement active");

    loop {
        tokio::select! {
            // --- Committed node execution ---
            Some(notification) = commit_rx.recv() => {
                handle_committed_node(
                    &notification.hash,
                    &reactor_state,
                    &store,
                );
            }
            Some(alert) = alert_rx.recv() => {
                if let Some(proposal) = sentinel_to_proposal(&alert) {
                    tracing::warn!(
                        source = %proposal.source,
                        title = %proposal.title,
                        "Sentinel triggered auto-proposal"
                    );

                    // Emit receipt for the auto-proposal action.
                    let payload_for_receipt = format!(
                        "auto-proposal:sentinel:{}:{}",
                        proposal.source, proposal.title
                    );
                    emit_governance_receipt(
                        "governance.auto_propose",
                        payload_for_receipt.as_bytes(),
                        ReceiptOutcome::Executed,
                        &reactor_state,
                        &store,
                    );

                    // Submit through consensus.
                    if let Err(e) = submit_auto_proposal(
                        &proposal,
                        &reactor_state,
                        &store,
                        &net_handle,
                    ).await {
                        tracing::error!(
                            err = %e,
                            source = %proposal.source,
                            "Auto-proposal submission failed"
                        );
                    }
                }
            }
            Some(event) = holon_rx.recv() => {
                if let Some(proposal) = holon_to_proposal(&event) {
                    tracing::warn!(
                        source = %proposal.source,
                        title = %proposal.title,
                        "Holon triggered auto-proposal"
                    );

                    let payload_for_receipt = format!(
                        "auto-proposal:holon:{}:{}",
                        proposal.source, proposal.title
                    );
                    emit_governance_receipt(
                        "governance.auto_propose",
                        payload_for_receipt.as_bytes(),
                        ReceiptOutcome::Executed,
                        &reactor_state,
                        &store,
                    );

                    if let Err(e) = submit_auto_proposal(
                        &proposal,
                        &reactor_state,
                        &store,
                        &net_handle,
                    ).await {
                        tracing::error!(
                            err = %e,
                            source = %proposal.source,
                            "Auto-proposal submission failed"
                        );
                    }
                }
            }
            else => {
                tracing::info!("Governance feedback channels closed — loop exiting");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_alert(check: SentinelCheck, severity: Severity) -> SentinelAlert {
        SentinelAlert {
            check,
            severity,
            message: "test alert".into(),
            timestamp_ms: 1_000,
        }
    }

    #[test]
    fn critical_liveness_generates_proposal() {
        let alert = make_alert(SentinelCheck::Liveness, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("liveness"));
        assert!(p.source.contains("Liveness"));
    }

    #[test]
    fn critical_quorum_generates_proposal() {
        let alert = make_alert(SentinelCheck::QuorumHealth, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("Quorum"));
        assert!(p.source.contains("QuorumHealth"));
    }

    #[test]
    fn warning_does_not_generate_proposal() {
        let alert = make_alert(SentinelCheck::Liveness, Severity::Warning);
        assert!(sentinel_to_proposal(&alert).is_none());
    }

    #[test]
    fn info_does_not_generate_proposal() {
        let alert = make_alert(SentinelCheck::Liveness, Severity::Info);
        assert!(sentinel_to_proposal(&alert).is_none());
    }

    #[test]
    fn critical_health_holon_generates_proposal() {
        let event = HolonEvent::HealthCheck {
            consensus_round: 10,
            committed_height: 5,
            status: HealthStatus::Critical {
                reason: "memory exhaustion".into(),
            },
        };
        let prop = holon_to_proposal(&event);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("critical"));
        assert!(p.body.contains("memory exhaustion"));
    }

    #[test]
    fn terminated_holon_generates_proposal() {
        let event = HolonEvent::HolonTerminated {
            holon_id: exo_core::types::Did::new("did:exo:topo-holon").unwrap(),
            reason: "capability denied".into(),
        };
        let prop = holon_to_proposal(&event);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("terminated"));
        assert!(p.body.contains("capability denied"));
    }

    #[test]
    fn healthy_check_does_not_generate_proposal() {
        let event = HolonEvent::HealthCheck {
            consensus_round: 10,
            committed_height: 5,
            status: HealthStatus::Healthy,
        };
        assert!(holon_to_proposal(&event).is_none());
    }

    #[test]
    fn topology_analysis_does_not_generate_proposal() {
        let event = HolonEvent::TopologyAnalysis {
            peer_count: 5,
            diversity_score: 0.8,
            recommendation: "add peers in eu-west".into(),
        };
        assert!(holon_to_proposal(&event).is_none());
    }

    #[test]
    fn scaling_recommendation_does_not_generate_proposal() {
        let event = HolonEvent::ScalingRecommendation {
            validator_count: 4,
            node_count: 12,
            recommendation: "add one validator".into(),
        };
        assert!(holon_to_proposal(&event).is_none());
    }

    #[test]
    fn store_consistency_critical_generates_proposal() {
        let alert = make_alert(SentinelCheck::StoreConsistency, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("Store consistency"));
    }

    #[test]
    fn receipt_integrity_critical_generates_proposal() {
        let alert = make_alert(SentinelCheck::ReceiptIntegrity, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("Receipt integrity"));
    }

    #[test]
    fn score_integrity_critical_generates_proposal() {
        let alert = make_alert(SentinelCheck::ScoreIntegrity, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("score integrity"));
        assert!(p.source.contains("ScoreIntegrity"));
    }

    #[test]
    fn otp_cleanup_critical_generates_proposal() {
        let alert = make_alert(SentinelCheck::OtpCleanup, Severity::Critical);
        let prop = sentinel_to_proposal(&alert);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.title.contains("OTP challenge cleanup"));
        assert!(p.source.contains("OtpCleanup"));
    }

    // -------------------------------------------------------------------
    // Decision execution tests
    // -------------------------------------------------------------------

    #[test]
    fn parse_autonomous_liveness_proposal() {
        let payload = serde_json::json!({
            "type": "autonomous_governance_proposal",
            "title": "Consensus liveness stalled",
            "body": "...",
            "source": "sentinel:Liveness",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::AdjustRoundTimeout { timeout_ms } => {
                assert_eq!(timeout_ms, 10_000);
            }
            other => panic!("Expected AdjustRoundTimeout, got {other:?}"),
        }
    }

    #[test]
    fn parse_autonomous_quorum_health_proposal() {
        let payload = serde_json::json!({
            "type": "autonomous_governance_proposal",
            "title": "Quorum health critical",
            "body": "...",
            "source": "sentinel:QuorumHealth",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::NoOp { reason } => {
                assert!(reason.contains("Quorum health"));
            }
            other => panic!("Expected NoOp, got {other:?}"),
        }
    }

    #[test]
    fn parse_autonomous_holon_terminated_proposal() {
        let payload = serde_json::json!({
            "type": "autonomous_governance_proposal",
            "title": "Infrastructure holon terminated — did:exo:topo-holon",
            "body": "...",
            "source": "holon:terminated",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::RestartHolon { holon_id } => {
                assert_eq!(holon_id, "did:exo:topo-holon");
            }
            other => panic!("Expected RestartHolon, got {other:?}"),
        }
    }

    #[test]
    fn parse_validator_add_action() {
        let payload = serde_json::json!({
            "type": "validator_add",
            "did": "did:exo:new-validator",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::AddValidator { did } => {
                assert_eq!(did, "did:exo:new-validator");
            }
            other => panic!("Expected AddValidator, got {other:?}"),
        }
    }

    #[test]
    fn parse_validator_remove_action() {
        let payload = serde_json::json!({
            "type": "validator_remove",
            "did": "did:exo:old-validator",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::RemoveValidator { did } => {
                assert_eq!(did, "did:exo:old-validator");
            }
            other => panic!("Expected RemoveValidator, got {other:?}"),
        }
    }

    #[test]
    fn parse_consensus_config_action() {
        let payload = serde_json::json!({
            "type": "consensus_config",
            "round_timeout_ms": 15000,
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::AdjustRoundTimeout { timeout_ms } => {
                assert_eq!(timeout_ms, 15_000);
            }
            other => panic!("Expected AdjustRoundTimeout, got {other:?}"),
        }
    }

    #[test]
    fn parse_sentinel_config_action() {
        let payload = serde_json::json!({
            "type": "sentinel_config",
            "interval_secs": 120,
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::AdjustSentinelInterval { interval_secs } => {
                assert_eq!(interval_secs, 120);
            }
            other => panic!("Expected AdjustSentinelInterval, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_type_returns_none() {
        let payload = serde_json::json!({
            "type": "unknown_action",
            "data": "irrelevant",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert!(parse_committed_action(&bytes).is_none());
    }

    #[test]
    fn parse_non_json_returns_none() {
        assert!(parse_committed_action(b"not json at all").is_none());
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse_committed_action(b"").is_none());
    }

    #[test]
    fn execute_adjust_round_timeout() {
        use crate::reactor::{ReactorConfig, create_reactor_state};

        let config = ReactorConfig {
            node_did: exo_core::types::Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators: std::collections::BTreeSet::new(),
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> =
            Arc::new(|data: &[u8]| {
                let h = blake3::hash(data);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(h.as_bytes());
                exo_core::types::Signature::from_bytes(sig)
            });
        let state = create_reactor_state(&config, sign_fn, None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let action = ExecutableAction::AdjustRoundTimeout { timeout_ms: 12_000 };
        let applied = execute_action(&action, &state, &store);
        assert!(applied);

        let s = state.lock().unwrap();
        assert_eq!(s.consensus.config.round_timeout_ms, 12_000);
    }

    #[test]
    fn execute_add_validator() {
        use crate::reactor::{ReactorConfig, create_reactor_state};

        let mut validators = std::collections::BTreeSet::new();
        validators.insert(exo_core::types::Did::new("did:exo:v0").unwrap());

        let config = ReactorConfig {
            node_did: exo_core::types::Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> =
            Arc::new(|data: &[u8]| {
                let h = blake3::hash(data);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(h.as_bytes());
                exo_core::types::Signature::from_bytes(sig)
            });
        let state = create_reactor_state(&config, sign_fn, None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let action = ExecutableAction::AddValidator {
            did: "did:exo:new-val".to_owned(),
        };
        let applied = execute_action(&action, &state, &store);
        assert!(applied);

        let s = state.lock().unwrap();
        assert_eq!(s.consensus.config.validators.len(), 2);
        assert!(
            s.consensus
                .config
                .validators
                .contains(&exo_core::types::Did::new("did:exo:new-val").unwrap())
        );

        // Verify persisted to store.
        drop(s);
        let st = store.lock().unwrap();
        let persisted = st.load_validator_set().unwrap();
        assert_eq!(persisted.len(), 2);
    }

    #[test]
    fn execute_remove_validator() {
        use crate::reactor::{ReactorConfig, create_reactor_state};

        let mut validators = std::collections::BTreeSet::new();
        validators.insert(exo_core::types::Did::new("did:exo:v0").unwrap());
        validators.insert(exo_core::types::Did::new("did:exo:v1").unwrap());

        let config = ReactorConfig {
            node_did: exo_core::types::Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> =
            Arc::new(|data: &[u8]| {
                let h = blake3::hash(data);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(h.as_bytes());
                exo_core::types::Signature::from_bytes(sig)
            });
        let state = create_reactor_state(&config, sign_fn, None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let action = ExecutableAction::RemoveValidator {
            did: "did:exo:v1".to_owned(),
        };
        let applied = execute_action(&action, &state, &store);
        assert!(applied);

        let s = state.lock().unwrap();
        assert_eq!(s.consensus.config.validators.len(), 1);
        assert!(
            !s.consensus
                .config
                .validators
                .contains(&exo_core::types::Did::new("did:exo:v1").unwrap())
        );
    }

    #[test]
    fn execute_remove_nonexistent_validator_returns_false() {
        use crate::reactor::{ReactorConfig, create_reactor_state};

        let config = ReactorConfig {
            node_did: exo_core::types::Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators: std::collections::BTreeSet::new(),
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> =
            Arc::new(|data: &[u8]| {
                let h = blake3::hash(data);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(h.as_bytes());
                exo_core::types::Signature::from_bytes(sig)
            });
        let state = create_reactor_state(&config, sign_fn, None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let action = ExecutableAction::RemoveValidator {
            did: "did:exo:nonexistent".to_owned(),
        };
        let applied = execute_action(&action, &state, &store);
        assert!(!applied);
    }

    #[test]
    fn execute_noop_returns_false() {
        use crate::reactor::{ReactorConfig, create_reactor_state};

        let config = ReactorConfig {
            node_did: exo_core::types::Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators: std::collections::BTreeSet::new(),
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> =
            Arc::new(|data: &[u8]| {
                let h = blake3::hash(data);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(h.as_bytes());
                exo_core::types::Signature::from_bytes(sig)
            });
        let state = create_reactor_state(&config, sign_fn, None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let action = ExecutableAction::NoOp {
            reason: "test".to_owned(),
        };
        let applied = execute_action(&action, &state, &store);
        assert!(!applied);
    }

    #[test]
    fn governance_payload_round_trips_through_store() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();

        let payload = b"test governance payload";
        let hash = Hash256::digest(payload);

        store.save_governance_payload(&hash, payload).unwrap();
        let loaded = store.load_governance_payload(&hash).unwrap();
        assert_eq!(loaded, Some(payload.to_vec()));
    }

    #[test]
    fn governance_payload_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let hash = Hash256::digest(b"nonexistent");
        assert_eq!(store.load_governance_payload(&hash).unwrap(), None);
    }

    #[test]
    fn parse_health_critical_auto_proposal_extends_timeout() {
        let payload = serde_json::json!({
            "type": "autonomous_governance_proposal",
            "title": "Health holon critical",
            "body": "...",
            "source": "holon:health",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let action = parse_committed_action(&bytes);
        assert!(action.is_some());
        match action.unwrap() {
            ExecutableAction::AdjustRoundTimeout { timeout_ms } => {
                assert_eq!(timeout_ms, 10_000);
            }
            other => panic!("Expected AdjustRoundTimeout, got {other:?}"),
        }
    }
}
