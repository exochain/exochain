//! Agentic sentinels — autonomous runtime verification agents.
//!
//! Each sentinel is a periodic background task that checks a specific
//! invariant and emits alerts when violations are detected.  Sentinels
//! operate autonomously — they do not require human input to run — but
//! forward alerts to the Telegram adjutant for human-in-the-loop oversight.
//!
//! ## Sentinels
//!
//! | Sentinel | Checks | Interval |
//! |----------|--------|----------|
//! | Liveness | Consensus round is advancing | 30s |
//! | QuorumHealth | Validator count >= 4 (BFT minimum) | 30s |
//! | ReceiptIntegrity | Recent receipts pass `verify_hash()` | 60s |
//! | StoreConsistency | Committed height matches certificate count | 60s |
//! | ScoreIntegrity | 0dentity scores are deterministically reproducible | 60s |

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use exo_core::hlc::HybridClock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{
    reactor::SharedReactorState,
    store::SqliteDagStore,
    zerodentity::{
        store::{SharedZerodentityStore, otp_challenge_expired},
        types::ZerodentityScore,
    },
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which invariant a sentinel checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelCheck {
    /// Consensus rounds are advancing.
    Liveness,
    /// Validator count meets BFT minimum (3f+1, min 4).
    QuorumHealth,
    /// Recent trust receipts pass hash verification.
    ReceiptIntegrity,
    /// Store committed height is consistent with certificate count.
    StoreConsistency,
    /// 0dentity scores are deterministically reproducible from their claim DAG.
    ///
    /// Spec §10.4 — samples up to 5 DIDs, recomputes, checks drift ≤ 10 bp.
    ScoreIntegrity,
    /// Expired OTP challenges still in `Pending` state are cleaned up.
    ///
    /// Spec §10.4 — ensures no stale challenges linger.
    OtpCleanup,
}

impl std::fmt::Display for SentinelCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Liveness => write!(f, "Liveness"),
            Self::QuorumHealth => write!(f, "QuorumHealth"),
            Self::ReceiptIntegrity => write!(f, "ReceiptIntegrity"),
            Self::StoreConsistency => write!(f, "StoreConsistency"),
            Self::ScoreIntegrity => write!(f, "ScoreIntegrity"),
            Self::OtpCleanup => write!(f, "OtpCleanup"),
        }
    }
}

/// Severity of a sentinel alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Severity {
    /// Informational — no action needed.
    Info,
    /// Warning — potential issue, monitor.
    Warning,
    /// Critical — requires immediate attention.
    Critical,
}

/// Result of a sentinel check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelStatus {
    pub check: SentinelCheck,
    pub healthy: bool,
    pub message: String,
    pub last_run_ms: u64,
}

/// Alert emitted when a sentinel detects a problem.
#[derive(Debug, Clone, Serialize)]
pub struct SentinelAlert {
    pub check: SentinelCheck,
    pub severity: Severity,
    pub message: String,
    pub timestamp_ms: u64,
}

/// Shared state holding all sentinel statuses.
pub type SharedSentinelState = Arc<Mutex<Vec<SentinelStatus>>>;

/// Channel for sentinel alerts → Telegram adjutant.
pub type AlertSender = mpsc::Sender<SentinelAlert>;
pub type AlertReceiver = mpsc::Receiver<SentinelAlert>;

type PreviousRound = Option<u64>;

pub(crate) fn now_ms() -> u64 {
    static SENTINEL_CLOCK: OnceLock<Mutex<HybridClock>> = OnceLock::new();
    let clock = SENTINEL_CLOCK.get_or_init(|| Mutex::new(HybridClock::new()));
    match clock.lock() {
        Ok(mut clock) => match clock.now() {
            Ok(timestamp) => timestamp.physical_ms,
            Err(err) => {
                tracing::error!(error = %err, "Sentinel HLC exhausted while reading timestamp");
                0
            }
        },
        Err(_) => {
            tracing::error!("Sentinel HLC mutex poisoned while reading timestamp");
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Sentinel checks
// ---------------------------------------------------------------------------

/// Check consensus liveness — round should be advancing.
fn check_liveness(reactor: &SharedReactorState, prev_round: &mut PreviousRound) -> SentinelStatus {
    let current_round = match reactor.lock() {
        Ok(s) => s.consensus.current_round,
        Err(_) => {
            tracing::error!("Reactor state mutex poisoned in liveness sentinel");
            return SentinelStatus {
                check: SentinelCheck::Liveness,
                healthy: false,
                message: "Reactor state mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    let previous_round = *prev_round;
    let (healthy, message) = match previous_round {
        None => (
            true,
            format!("Consensus round {current_round} — baseline recorded"),
        ),
        Some(previous) if current_round > previous => (
            true,
            format!("Consensus round {previous} -> {current_round} — advancing normally"),
        ),
        Some(previous) if current_round == previous => (
            false,
            format!("Consensus round {current_round} == previous {previous} — stalled"),
        ),
        Some(previous) => (
            false,
            format!("Consensus round {current_round} < previous {previous} — possible regression"),
        ),
    };
    if healthy {
        *prev_round = Some(current_round);
    }

    SentinelStatus {
        check: SentinelCheck::Liveness,
        healthy,
        message,
        last_run_ms: now_ms(),
    }
}

/// Check quorum health — minimum 4 validators for BFT safety.
fn check_quorum_health(reactor: &SharedReactorState) -> SentinelStatus {
    let validator_count = match reactor.lock() {
        Ok(s) => s.consensus.config.validators.len(),
        Err(_) => {
            tracing::error!("Reactor state mutex poisoned in quorum sentinel");
            return SentinelStatus {
                check: SentinelCheck::QuorumHealth,
                healthy: false,
                message: "Reactor state mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    let healthy = validator_count >= 4;
    let message = if healthy {
        format!("{validator_count} validators — quorum healthy")
    } else {
        format!("{validator_count} validators — BELOW BFT MINIMUM (need >= 4)")
    };

    SentinelStatus {
        check: SentinelCheck::QuorumHealth,
        healthy,
        message,
        last_run_ms: now_ms(),
    }
}

const RECEIPT_INTEGRITY_SAMPLE_LIMIT: u32 = 10;

/// Spot-check recent trust receipts for hash integrity.
fn check_receipt_integrity(store: &Arc<Mutex<SqliteDagStore>>) -> SentinelStatus {
    let st = match store.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("Store mutex poisoned in receipt integrity sentinel");
            return SentinelStatus {
                check: SentinelCheck::ReceiptIntegrity,
                healthy: false,
                message: "Store mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    let receipts = match st.load_recent_receipts(RECEIPT_INTEGRITY_SAMPLE_LIMIT) {
        Ok(receipts) => receipts,
        Err(e) => {
            tracing::error!(err = %e, "Failed to load receipts in receipt integrity sentinel");
            return SentinelStatus {
                check: SentinelCheck::ReceiptIntegrity,
                healthy: false,
                message: format!("Receipt store unavailable: {e}"),
                last_run_ms: now_ms(),
            };
        }
    };

    if receipts.is_empty() {
        return SentinelStatus {
            check: SentinelCheck::ReceiptIntegrity,
            healthy: true,
            message: "No trust receipts available for integrity check".into(),
            last_run_ms: now_ms(),
        };
    }

    for receipt in &receipts {
        match receipt.verify_hash() {
            Ok(true) => {}
            Ok(false) => {
                return SentinelStatus {
                    check: SentinelCheck::ReceiptIntegrity,
                    healthy: false,
                    message: format!(
                        "Receipt hash verification failed for {}",
                        receipt.receipt_hash
                    ),
                    last_run_ms: now_ms(),
                };
            }
            Err(e) => {
                return SentinelStatus {
                    check: SentinelCheck::ReceiptIntegrity,
                    healthy: false,
                    message: format!(
                        "Receipt hash verification error for {}: {e}",
                        receipt.receipt_hash
                    ),
                    last_run_ms: now_ms(),
                };
            }
        }
    }

    SentinelStatus {
        check: SentinelCheck::ReceiptIntegrity,
        healthy: true,
        message: format!("Verified {} recent trust receipt hash(es)", receipts.len()),
        last_run_ms: now_ms(),
    }
}

/// Check 0dentity score integrity — recompute scores for sampled DIDs and
/// verify they match the stored values within a 10 bp tolerance.
///
/// Spec §10.4.
fn check_score_integrity(zerodentity: &SharedZerodentityStore) -> SentinelStatus {
    let zstore = match zerodentity.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("Zerodentity store mutex poisoned in score integrity sentinel");
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: false,
                message: "Zerodentity store mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    // Fast path: no scored DIDs yet.
    if zstore.scored_did_count() == 0 {
        return SentinelStatus {
            check: SentinelCheck::ScoreIntegrity,
            healthy: true,
            message: "No scored DIDs yet — integrity check skipped".into(),
            last_run_ms: now_ms(),
        };
    }

    // Sample one DID, collect all data needed for recompute, then drop the lock.
    let sample = zstore.sample_scored_dids(1);
    let did = match sample.first() {
        Some(d) => d.clone(),
        None => {
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: true,
                message: "No scored DIDs yet — integrity check skipped".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    let stored = match zstore.get_score(&did) {
        Some(s) => s.clone(),
        None => {
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: true,
                message: "Score vanished between sample and read — skipping".into(),
                last_run_ms: now_ms(),
            };
        }
    };

    // Extract plain IdentityClaims from (claim_id, claim) tuples.
    let raw_claims = match zstore.get_claims(&did) {
        Ok(claims) => claims,
        Err(e) => {
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: false,
                message: format!(
                    "Zerodentity claims unavailable for DID {}: {e}",
                    did.as_str()
                ),
                last_run_ms: now_ms(),
            };
        }
    };
    let claims_plain: Vec<crate::zerodentity::types::IdentityClaim> =
        raw_claims.into_iter().map(|(_, c)| c).collect();
    let fingerprints = match zstore.get_fingerprints(&did) {
        Ok(fingerprints) => fingerprints,
        Err(e) => {
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: false,
                message: format!(
                    "Zerodentity fingerprints unavailable for DID {}: {e}",
                    did.as_str()
                ),
                last_run_ms: now_ms(),
            };
        }
    };
    let behavioral = match zstore.get_behavioral_samples(&did) {
        Ok(behavioral) => behavioral,
        Err(e) => {
            return SentinelStatus {
                check: SentinelCheck::ScoreIntegrity,
                healthy: false,
                message: format!(
                    "Zerodentity behavioral samples unavailable for DID {}: {e}",
                    did.as_str()
                ),
                last_run_ms: now_ms(),
            };
        }
    };

    // Release the lock before running compute (can be non-trivial).
    drop(zstore);

    let recomputed = ZerodentityScore::compute(
        &did,
        &claims_plain,
        &fingerprints,
        &behavioral,
        stored.computed_ms,
    );

    // Drift tolerance: 10 bp (≈ 0.1% of the 0–100 scale).
    // The algorithm is deterministic so any drift indicates corruption.
    let drift = stored.composite.abs_diff(recomputed.composite);
    if drift > 10 {
        return SentinelStatus {
            check: SentinelCheck::ScoreIntegrity,
            healthy: false,
            message: format!(
                "Score drift {drift} bp detected for DID {} (stored={}, recomputed={})",
                did.as_str(),
                stored.composite,
                recomputed.composite
            ),
            last_run_ms: now_ms(),
        };
    }

    SentinelStatus {
        check: SentinelCheck::ScoreIntegrity,
        healthy: true,
        message: format!(
            "Score integrity verified — DID {} checked (drift {drift} bp)",
            did.as_str()
        ),
        last_run_ms: now_ms(),
    }
}

/// Check for expired OTP challenges still in `Pending` state and clean them up.
///
/// Spec §10.4 — ensures no stale challenges linger in memory.
fn check_otp_cleanup(zerodentity: &SharedZerodentityStore) -> SentinelStatus {
    let mut zstore = match zerodentity.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("Zerodentity store mutex poisoned in OTP cleanup sentinel");
            return SentinelStatus {
                check: SentinelCheck::OtpCleanup,
                healthy: false,
                message: "Zerodentity store mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };
    let now = now_ms();

    // Count expired-but-pending challenges before cleanup
    let expired_pending = zstore
        .all_otp_challenges()
        .iter()
        .filter(|ch| {
            let expired = otp_challenge_expired(ch, now);
            let pending = ch.state == crate::zerodentity::types::OtpState::Pending;
            expired && pending
        })
        .count();

    if expired_pending == 0 {
        return SentinelStatus {
            check: SentinelCheck::OtpCleanup,
            healthy: true,
            message: "No expired pending OTP challenges".into(),
            last_run_ms: now,
        };
    }

    let cleaned = zstore.cleanup_expired_otp(now);

    SentinelStatus {
        check: SentinelCheck::OtpCleanup,
        healthy: true,
        message: format!("Cleaned up {cleaned} expired OTP challenge(s)"),
        last_run_ms: now,
    }
}

/// Check store consistency — committed height vs certificate count.
fn check_store_consistency(store: &Arc<Mutex<SqliteDagStore>>) -> SentinelStatus {
    let st = match store.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("Store mutex poisoned in consistency sentinel");
            return SentinelStatus {
                check: SentinelCheck::StoreConsistency,
                healthy: false,
                message: "Store mutex poisoned".into(),
                last_run_ms: now_ms(),
            };
        }
    };
    let height = match st.committed_height_value() {
        Ok(height) => height,
        Err(e) => {
            tracing::error!(err = %e, "Failed to read committed height in consistency sentinel");
            return SentinelStatus {
                check: SentinelCheck::StoreConsistency,
                healthy: false,
                message: format!("Store unavailable: {e}"),
                last_run_ms: now_ms(),
            };
        }
    };
    let certs = match st.load_certificates() {
        Ok(certs) => certs,
        Err(e) => {
            tracing::error!(err = %e, "Failed to load commit certificates in consistency sentinel");
            return SentinelStatus {
                check: SentinelCheck::StoreConsistency,
                healthy: false,
                message: format!("Store certificates unavailable: {e}"),
                last_run_ms: now_ms(),
            };
        }
    };

    let cert_count = match u64::try_from(certs.len()) {
        Ok(count) => count,
        Err(_) => {
            return SentinelStatus {
                check: SentinelCheck::StoreConsistency,
                healthy: false,
                message: format!(
                    "Store certificate count {} exceeds u64 comparison range",
                    certs.len()
                ),
                last_run_ms: now_ms(),
            };
        }
    };

    let healthy = cert_count <= height || height == 0;
    let message = if healthy {
        format!("Store consistent — height {height}, {cert_count} certificates")
    } else {
        format!("Store inconsistency — height {height} but {cert_count} certificates")
    };

    SentinelStatus {
        check: SentinelCheck::StoreConsistency,
        healthy,
        message,
        last_run_ms: now_ms(),
    }
}

fn sentinel_task_failed_statuses(message: String) -> Vec<SentinelStatus> {
    [
        SentinelCheck::Liveness,
        SentinelCheck::QuorumHealth,
        SentinelCheck::ReceiptIntegrity,
        SentinelCheck::StoreConsistency,
        SentinelCheck::ScoreIntegrity,
        SentinelCheck::OtpCleanup,
    ]
    .into_iter()
    .map(|check| SentinelStatus {
        check,
        healthy: false,
        message: message.clone(),
        last_run_ms: now_ms(),
    })
    .collect()
}

fn collect_sentinel_statuses(
    reactor: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    zerodentity: &SharedZerodentityStore,
    prev_round: &mut PreviousRound,
) -> Vec<SentinelStatus> {
    vec![
        check_liveness(reactor, prev_round),
        check_quorum_health(reactor),
        check_receipt_integrity(store),
        check_store_consistency(store),
        check_score_integrity(zerodentity),
        check_otp_cleanup(zerodentity),
    ]
}

async fn collect_sentinel_statuses_blocking(
    reactor: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    zerodentity: SharedZerodentityStore,
    prev_round: PreviousRound,
) -> (Vec<SentinelStatus>, PreviousRound) {
    tokio::task::spawn_blocking(move || {
        let mut next_prev_round = prev_round;
        let statuses =
            collect_sentinel_statuses(&reactor, &store, &zerodentity, &mut next_prev_round);
        (statuses, next_prev_round)
    })
    .await
    .unwrap_or_else(|e| {
        let message = format!("Sentinel check task failed: {e}");
        (sentinel_task_failed_statuses(message), prev_round)
    })
}

fn replace_sentinel_state_sync(state: SharedSentinelState, statuses: Vec<SentinelStatus>) {
    match state.lock() {
        Ok(mut ss) => *ss = statuses,
        Err(_) => tracing::error!("Sentinel state mutex poisoned — skipping update"),
    }
}

async fn replace_sentinel_state(state: SharedSentinelState, statuses: Vec<SentinelStatus>) {
    if let Err(e) =
        tokio::task::spawn_blocking(move || replace_sentinel_state_sync(state, statuses)).await
    {
        tracing::error!(err = %e, "Sentinel state update task failed");
    }
}

// ---------------------------------------------------------------------------
// Sentinel loop
// ---------------------------------------------------------------------------

/// Run all sentinels as a single background Tokio task.
///
/// Checks run every `interval` and update `sentinel_state`.  Unhealthy
/// results are forwarded to `alert_tx` for the Telegram adjutant.
pub async fn run_sentinel_loop(
    reactor: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    zerodentity: SharedZerodentityStore,
    sentinel_state: SharedSentinelState,
    alert_tx: AlertSender,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev_round = None;

    loop {
        ticker.tick().await;

        let (statuses, next_prev_round) = collect_sentinel_statuses_blocking(
            Arc::clone(&reactor),
            Arc::clone(&store),
            Arc::clone(&zerodentity),
            prev_round,
        )
        .await;
        prev_round = next_prev_round;

        // Emit alerts for unhealthy sentinels.
        for status in &statuses {
            if !status.healthy {
                let severity = match status.check {
                    SentinelCheck::QuorumHealth => Severity::Critical,
                    SentinelCheck::Liveness => Severity::Warning,
                    SentinelCheck::ScoreIntegrity => Severity::Warning,
                    SentinelCheck::OtpCleanup => Severity::Info,
                    _ => Severity::Warning,
                };
                let alert = SentinelAlert {
                    check: status.check.clone(),
                    severity,
                    message: status.message.clone(),
                    timestamp_ms: now_ms(),
                };
                if alert_tx.send(alert).await.is_err() {
                    tracing::warn!(
                        check = %status.check,
                        "Alert channel closed — sentinel alert dropped"
                    );
                }
            }
        }

        // Update shared state.
        replace_sentinel_state(Arc::clone(&sentinel_state), statuses).await;
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

fn clone_sentinel_state_sync(
    state: SharedSentinelState,
) -> Result<Vec<SentinelStatus>, StatusCode> {
    let ss = state.lock().map_err(|_| {
        tracing::error!("Sentinel state mutex poisoned in status handler");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(ss.clone())
}

async fn load_sentinel_statuses(
    state: SharedSentinelState,
) -> Result<Vec<SentinelStatus>, StatusCode> {
    tokio::task::spawn_blocking(move || clone_sentinel_state_sync(state))
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "Sentinel status load task failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
}

/// `GET /api/v1/sentinels` — current sentinel status.
async fn handle_sentinel_status(
    State(state): State<SharedSentinelState>,
) -> Result<Json<Vec<SentinelStatus>>, StatusCode> {
    load_sentinel_statuses(state).await.map(Json)
}

/// Build the sentinel API router.
pub fn sentinel_router(state: SharedSentinelState) -> Router {
    Router::new()
        .route("/api/v1/sentinels", get(handle_sentinel_status))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use exo_core::types::{Did, Hash256, Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        reactor::{ReactorConfig, create_reactor_state},
        store::SqliteDagStore,
    };

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        Arc::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn test_reactor() -> SharedReactorState {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };
        create_reactor_state(&config, make_sign_fn(), None)
    }

    fn test_store() -> Arc<Mutex<SqliteDagStore>> {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        std::mem::forget(dir);
        Arc::new(Mutex::new(store))
    }

    fn store_with_negative_committed_height() -> Arc<Mutex<SqliteDagStore>> {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        let hash = [0xA5u8; 32];
        conn.execute(
            "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
            rusqlite::params![hash.as_slice(), -1_i64],
        )
        .unwrap();
        std::mem::forget(dir);
        Arc::new(Mutex::new(store))
    }

    fn store_with_malformed_receipt() -> Arc<Mutex<SqliteDagStore>> {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        let receipt_hash = Hash256::digest(b"malformed-receipt");
        conn.execute(
            "INSERT INTO trust_receipts
             (receipt_hash, actor_did, action_type, outcome, timestamp_ms, cbor_data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                receipt_hash.0.as_slice(),
                "did:exo:actor-a",
                "dag.commit",
                "Executed",
                1_700_000_000_000_i64,
                [0xff_u8].as_slice(),
            ],
        )
        .unwrap();
        std::mem::forget(dir);
        Arc::new(Mutex::new(store))
    }

    #[test]
    fn score_integrity_sentinel_does_not_discard_zerodentity_read_errors() {
        let source = include_str!("sentinels.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let score_integrity = production
            .split("fn check_score_integrity")
            .nth(1)
            .and_then(|section| section.split("fn check_otp_cleanup").next())
            .unwrap();

        assert!(!score_integrity.contains(".unwrap_or_default()"));
    }

    #[test]
    fn sentinel_async_paths_do_not_lock_std_mutexes_directly() {
        let source = include_str!("sentinels.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "sentinel async paths must isolate synchronous mutex/store work from Tokio workers"
        );

        let loop_body = production
            .split("pub async fn run_sentinel_loop")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------\n// API").next())
            .unwrap();
        assert!(
            !loop_body.contains(".lock()"),
            "sentinel loop must not directly lock std::sync::Mutex inside async context"
        );

        let handler_body = production
            .split("async fn handle_sentinel_status")
            .nth(1)
            .and_then(|section| section.split("/// Build the sentinel API router.").next())
            .unwrap();
        assert!(
            !handler_body.contains(".lock()"),
            "sentinel status handler must not directly lock std::sync::Mutex inside async context"
        );
    }

    #[test]
    fn score_integrity_fails_closed_on_claim_read_error() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:scored").unwrap();
            let mut store = zerodentity.lock().unwrap();
            store.put_score(ZerodentityScore::compute(&did, &[], &[], &[], 1000));
            store.inject_read_failure(crate::zerodentity::store::ZerodentityReadFailure::Claims);
        }

        let status = check_score_integrity(&zerodentity);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ScoreIntegrity);
        assert!(status.message.contains("Zerodentity claims unavailable"));
    }

    #[test]
    fn score_integrity_fails_closed_on_fingerprint_read_error() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:scored").unwrap();
            let mut store = zerodentity.lock().unwrap();
            store.put_score(ZerodentityScore::compute(&did, &[], &[], &[], 1000));
            store.inject_read_failure(
                crate::zerodentity::store::ZerodentityReadFailure::Fingerprints,
            );
        }

        let status = check_score_integrity(&zerodentity);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ScoreIntegrity);
        assert!(
            status
                .message
                .contains("Zerodentity fingerprints unavailable")
        );
    }

    #[test]
    fn score_integrity_fails_closed_on_behavioral_read_error() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:scored").unwrap();
            let mut store = zerodentity.lock().unwrap();
            store.put_score(ZerodentityScore::compute(&did, &[], &[], &[], 1000));
            store
                .inject_read_failure(crate::zerodentity::store::ZerodentityReadFailure::Behavioral);
        }

        let status = check_score_integrity(&zerodentity);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ScoreIntegrity);
        assert!(
            status
                .message
                .contains("Zerodentity behavioral samples unavailable")
        );
    }

    #[test]
    fn score_integrity_verifies_matching_score() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:scored").unwrap();
            let mut store = zerodentity.lock().unwrap();
            store.put_score(ZerodentityScore::compute(&did, &[], &[], &[], 1000));
        }

        let status = check_score_integrity(&zerodentity);

        assert!(status.healthy);
        assert_eq!(status.check, SentinelCheck::ScoreIntegrity);
        assert!(status.message.contains("Score integrity verified"));
    }

    #[test]
    fn score_integrity_detects_score_drift() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:scored").unwrap();
            let mut score = ZerodentityScore::compute(&did, &[], &[], &[], 1000);
            score.composite = score.composite.saturating_add(1000).min(10_000);
            let mut store = zerodentity.lock().unwrap();
            store.put_score(score);
        }

        let status = check_score_integrity(&zerodentity);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ScoreIntegrity);
        assert!(status.message.contains("Score drift"));
    }

    #[test]
    fn otp_cleanup_reports_clean_when_no_expired_pending_challenges() {
        let zerodentity = crate::zerodentity::store::new_shared_store();

        let status = check_otp_cleanup(&zerodentity);

        assert!(status.healthy);
        assert_eq!(status.check, SentinelCheck::OtpCleanup);
        assert_eq!(status.message, "No expired pending OTP challenges");
    }

    #[test]
    fn otp_cleanup_removes_expired_pending_challenges() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let now = now_ms();
            let challenge = crate::zerodentity::types::OtpChallenge {
                challenge_id: "expired-otp".into(),
                subject_did: Did::new("did:exo:otp").unwrap(),
                channel: crate::zerodentity::types::OtpChannel::Email,
                hmac_secret: crate::zerodentity::types::OtpHmacSecret::new([7u8; 32]).unwrap(),
                dispatched_ms: now.saturating_sub(10_000),
                ttl_ms: 1,
                attempts: 0,
                max_attempts: 3,
                state: crate::zerodentity::types::OtpState::Pending,
            };
            zerodentity
                .lock()
                .unwrap()
                .insert_otp_challenge(&challenge)
                .unwrap();
        }

        let status = check_otp_cleanup(&zerodentity);

        assert!(status.healthy);
        assert_eq!(status.check, SentinelCheck::OtpCleanup);
        assert!(
            status
                .message
                .contains("Cleaned up 1 expired OTP challenge")
        );
        assert!(zerodentity.lock().unwrap().all_otp_challenges().is_empty());
    }

    #[test]
    fn otp_cleanup_removes_pending_challenge_when_expiry_overflows() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let challenge = crate::zerodentity::types::OtpChallenge {
                challenge_id: "overflow-otp".into(),
                subject_did: Did::new("did:exo:otp-overflow").unwrap(),
                channel: crate::zerodentity::types::OtpChannel::Email,
                hmac_secret: crate::zerodentity::types::OtpHmacSecret::new([8u8; 32]).unwrap(),
                dispatched_ms: u64::MAX,
                ttl_ms: 1,
                attempts: 0,
                max_attempts: 3,
                state: crate::zerodentity::types::OtpState::Pending,
            };
            zerodentity
                .lock()
                .unwrap()
                .insert_otp_challenge(&challenge)
                .unwrap();
        }

        let status = check_otp_cleanup(&zerodentity);

        assert!(status.healthy);
        assert_eq!(status.check, SentinelCheck::OtpCleanup);
        assert!(
            status
                .message
                .contains("Cleaned up 1 expired OTP challenge")
        );
        assert!(zerodentity.lock().unwrap().all_otp_challenges().is_empty());
    }

    #[test]
    fn liveness_check_healthy() {
        let reactor = test_reactor();
        let mut prev = None;
        let status = check_liveness(&reactor, &mut prev);
        assert!(status.healthy);
        assert_eq!(status.check, SentinelCheck::Liveness);
        assert_eq!(prev, Some(0));
    }

    #[test]
    fn liveness_check_detects_stalled_round_after_baseline() {
        let reactor = test_reactor();
        let mut prev = None;

        let baseline = check_liveness(&reactor, &mut prev);
        assert!(baseline.healthy);

        let stalled = check_liveness(&reactor, &mut prev);

        assert!(!stalled.healthy);
        assert_eq!(stalled.check, SentinelCheck::Liveness);
        assert!(
            stalled.message.contains("stalled"),
            "stalled liveness message should explain equal rounds: {}",
            stalled.message
        );
        assert_eq!(prev, Some(0));
    }

    #[test]
    fn liveness_check_accepts_strictly_advanced_round() {
        let reactor = test_reactor();
        let mut prev = None;

        let baseline = check_liveness(&reactor, &mut prev);
        assert!(baseline.healthy);
        reactor.lock().unwrap().consensus.current_round = 1;

        let advanced = check_liveness(&reactor, &mut prev);

        assert!(advanced.healthy);
        assert_eq!(advanced.check, SentinelCheck::Liveness);
        assert_eq!(prev, Some(1));
    }

    #[test]
    fn quorum_health_with_four_validators() {
        let reactor = test_reactor();
        let status = check_quorum_health(&reactor);
        assert!(status.healthy);
    }

    #[test]
    fn quorum_health_below_minimum() {
        let validators: BTreeSet<Did> = (0..3)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };
        let reactor = create_reactor_state(&config, make_sign_fn(), None);
        let status = check_quorum_health(&reactor);
        assert!(!status.healthy);
        assert!(status.message.contains("BELOW BFT MINIMUM"));
    }

    #[test]
    fn store_consistency_empty_store() {
        let store = test_store();
        let status = check_store_consistency(&store);
        assert!(status.healthy);
    }

    #[test]
    fn store_consistency_does_not_use_truncating_certificate_count_cast() {
        let source = include_str!("sentinels.rs");
        let check_store_consistency_section = source
            .split("fn check_store_consistency")
            .nth(1)
            .and_then(|section| section.split("fn collect_sentinel_statuses").next())
            .unwrap();

        assert!(
            !check_store_consistency_section.contains("certs.len() as u64"),
            "certificate count comparison must use checked conversion, not a truncating cast"
        );
    }

    #[test]
    fn production_sentinel_source_does_not_suppress_integer_conversion_lints() {
        let source = include_str!("sentinels.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            !production.contains("clippy::as_conversions"),
            "production sentinel source must not suppress integer conversion lints"
        );
    }

    #[test]
    fn receipt_integrity_source_verifies_receipt_hashes() {
        let source = include_str!("sentinels.rs");
        let receipt_integrity = source
            .split("fn check_receipt_integrity")
            .nth(1)
            .and_then(|section| section.split("fn check_score_integrity").next())
            .unwrap();

        assert!(
            receipt_integrity.contains(".verify_hash()"),
            "ReceiptIntegrity sentinel must verify persisted trust receipt hashes"
        );
    }

    #[test]
    fn receipt_integrity_empty_store() {
        let store = test_store();
        let status = check_receipt_integrity(&store);
        assert!(status.healthy);
    }

    #[test]
    fn receipt_integrity_fails_closed_on_receipt_decode_error() {
        let store = store_with_malformed_receipt();
        let status = check_receipt_integrity(&store);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ReceiptIntegrity);
        assert!(status.message.contains("CBOR decode receipt"));
    }

    #[test]
    fn receipt_integrity_detects_tampered_receipt_hash() {
        use exo_core::types::{ReceiptOutcome, Timestamp, TrustReceipt};

        let store = test_store();
        let sign_fn = make_sign_fn();
        let mut receipt = TrustReceipt::new(
            Did::new("did:exo:actor-a").unwrap(),
            Hash256::digest(b"authority"),
            None,
            "dag.commit".to_string(),
            Hash256::digest(b"action-payload"),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: 1_700_000_000_000,
                logical: 0,
            },
            &*sign_fn,
        )
        .expect("test trust receipt should encode");
        receipt.action_type = "dag.commit.tampered".to_string();
        assert!(!receipt.verify_hash().unwrap());
        store.lock().unwrap().save_receipt(&receipt).unwrap();

        let status = check_receipt_integrity(&store);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::ReceiptIntegrity);
        assert!(status.message.contains("hash verification failed"));
    }

    #[test]
    fn store_consistency_fails_closed_on_store_height_error() {
        let store = store_with_negative_committed_height();
        let status = check_store_consistency(&store);

        assert!(!status.healthy);
        assert_eq!(status.check, SentinelCheck::StoreConsistency);
        assert!(status.message.contains("committed.height"));
    }

    #[tokio::test]
    async fn sentinel_api_returns_status() {
        let state: SharedSentinelState = Arc::new(Mutex::new(vec![
            SentinelStatus {
                check: SentinelCheck::Liveness,
                healthy: true,
                message: "ok".into(),
                last_run_ms: 1000,
            },
            SentinelStatus {
                check: SentinelCheck::QuorumHealth,
                healthy: false,
                message: "low".into(),
                last_run_ms: 1000,
            },
        ]));

        let app = sentinel_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sentinels")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let results: Vec<SentinelStatus> = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].healthy);
        assert!(!results[1].healthy);
    }

    #[tokio::test]
    async fn sentinel_loop_updates_state_and_emits_unhealthy_alert() {
        let validators: BTreeSet<Did> = (0..3)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };
        let reactor = create_reactor_state(&config, make_sign_fn(), None);
        let store = test_store();
        let zerodentity = crate::zerodentity::store::new_shared_store();
        let sentinel_state: SharedSentinelState = Arc::new(Mutex::new(Vec::new()));
        let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel(4);

        let task = tokio::spawn(run_sentinel_loop(
            reactor,
            store,
            zerodentity,
            Arc::clone(&sentinel_state),
            alert_tx,
            Duration::from_millis(50),
        ));

        let alert = tokio::time::timeout(Duration::from_secs(1), alert_rx.recv())
            .await
            .unwrap()
            .unwrap();

        task.abort();
        let aborted = task.await.unwrap_err();
        assert!(aborted.is_cancelled());

        assert_eq!(alert.check, SentinelCheck::QuorumHealth);
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("BELOW BFT MINIMUM"));

        let statuses = sentinel_state.lock().unwrap().clone();
        assert_eq!(statuses.len(), 6);
        assert!(statuses.iter().any(|status| {
            status.check == SentinelCheck::QuorumHealth
                && !status.healthy
                && status.message.contains("BELOW BFT MINIMUM")
        }));
    }
}
