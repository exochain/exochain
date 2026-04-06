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
// Feedback loop task
// ---------------------------------------------------------------------------

/// Spawn the governance feedback loop.
///
/// Consumes sentinel alerts and holon events, converting critical signals
/// into governance proposals and emitting trust receipts for every
/// autonomous action. This closes the self-improvement loop:
///
/// ```text
/// Monitor → Propose → Decide → Execute → Audit
/// ```
pub async fn run_feedback_loop(
    mut alert_rx: tokio::sync::mpsc::Receiver<SentinelAlert>,
    mut holon_rx: tokio::sync::mpsc::Receiver<HolonEvent>,
    reactor_state: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    net_handle: NetworkHandle,
) {
    tracing::info!("Governance feedback loop started — autonomous self-improvement active");

    loop {
        tokio::select! {
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
}
