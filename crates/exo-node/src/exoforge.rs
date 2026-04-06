//! ExoForge — Autonomous Build Orchestration Engine.
//!
//! Takes a specification document and decomposes it into a phased task
//! graph, assigns agents, tracks progress, and surfaces a real-time
//! mission-control dashboard.  Escalation paths: Council, AI-IRB, Human.
//!
//! ## Routes
//!
//! | Method | Path                              | Description              |
//! |--------|-----------------------------------|--------------------------|
//! | GET    | `/exoforge`                       | Dashboard (HTML)         |
//! | GET    | `/api/v1/forge/tasks`             | List all tasks           |
//! | GET    | `/api/v1/forge/stats`             | Aggregate statistics     |
//! | POST   | `/api/v1/forge/tasks/:id/status`  | Update task status       |
//! | POST   | `/api/v1/forge/tasks/:id/assign`  | Assign agent to task     |
//! | POST   | `/api/v1/forge/tasks/:id/escalate`| Escalate a task          |
//! | POST   | `/api/v1/forge/log`               | Append activity log      |

#![allow(clippy::as_conversions, clippy::float_arithmetic)]

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

// ─── Types ──────────────────────────────────────────────────────────

/// Thread-safe shared handle to the forge orchestration state.
pub type SharedForgeState = Arc<Mutex<ForgeState>>;

/// A single task in the build orchestration graph, tracking phase, status, and agent assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeTask {
    pub id: u32,
    pub phase: u32,
    pub phase_name: String,
    pub title: String,
    pub description: String,
    pub spec_section: String,
    pub status: TaskStatus,
    pub agent: Option<String>,
    pub escalation: EscalationLevel,
    pub depends_on_phase: Option<u32>,
    pub started_ms: Option<u64>,
    pub completed_ms: Option<u64>,
}

/// Lifecycle status of a forge task (Queued -> Assigned -> InProgress -> Review -> Complete).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Queued,
    Assigned,
    InProgress,
    Review,
    Complete,
    Blocked,
    Escalated,
}

/// Escalation tier for a blocked or contested task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationLevel {
    None,
    Council,
    AiIrb,
    Human,
}

/// A timestamped entry in the forge activity log, optionally linked to a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp_ms: u64,
    pub message: String,
    pub task_id: Option<u32>,
}

/// Aggregate statistics across all forge tasks, including per-phase breakdowns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeStats {
    pub total: u32,
    pub queued: u32,
    pub assigned: u32,
    pub in_progress: u32,
    pub review: u32,
    pub complete: u32,
    pub blocked: u32,
    pub escalated: u32,
    pub percent_complete: f64,
    pub phases: Vec<PhaseStats>,
}

/// Completion statistics for a single build phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStats {
    pub phase: u32,
    pub name: String,
    pub total: u32,
    pub complete: u32,
    pub percent: f64,
}

/// Mutable state for the forge orchestrator: task graph, activity log, and spec metadata.
pub struct ForgeState {
    pub spec_name: String,
    #[allow(dead_code)]
    pub spec_path: String,
    pub tasks: Vec<ForgeTask>,
    pub activity_log: Vec<ActivityEntry>,
    #[allow(dead_code)]
    pub started_ms: u64,
}

// ─── Request / Response bodies ──────────────────────────────────────

/// Request body for updating a task's status.
#[derive(Deserialize)]
pub struct StatusUpdate {
    pub status: TaskStatus,
}

/// Request body for assigning an agent to a task.
#[derive(Deserialize)]
pub struct AgentAssignment {
    pub agent: String,
}

/// Request body for escalating a task to a higher authority tier.
#[derive(Deserialize)]
pub struct EscalateRequest {
    pub level: EscalationLevel,
    pub reason: String,
}

/// Request body for appending a message to the forge activity log.
#[derive(Deserialize)]
pub struct LogEntry {
    pub message: String,
    pub task_id: Option<u32>,
}

// ─── State Initialization ───────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl ForgeState {
    /// Create a new forge state pre-loaded with the 0DENTITY spec task graph.
    pub fn new_zerodentity() -> Self {
        let tasks = build_zerodentity_tasks();
        let started = now_ms();
        ForgeState {
            spec_name: "0DENTITY-APP-SPEC.md".into(),
            spec_path: "docs/0DENTITY-APP-SPEC.md".into(),
            tasks,
            activity_log: vec![
                ActivityEntry {
                    timestamp_ms: started,
                    message: "ExoForge initialized — spec loaded: 0DENTITY-APP-SPEC.md (2,221 lines, 14 sections)".into(),
                    task_id: None,
                },
                ActivityEntry {
                    timestamp_ms: started + 1,
                    message: "Task graph decomposed: 56 tasks across 12 phases".into(),
                    task_id: None,
                },
                ActivityEntry {
                    timestamp_ms: started + 2,
                    message: "Awaiting agent assignment — orchestrator monitoring".into(),
                    task_id: None,
                },
            ],
            started_ms: started,
        }
    }

    /// Compute aggregate and per-phase completion statistics from the current task list.
    pub fn stats(&self) -> ForgeStats {
        let total = self.tasks.len() as u32;
        let queued = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Queued)
            .count() as u32;
        let assigned = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Assigned)
            .count() as u32;
        let in_progress = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::InProgress)
            .count() as u32;
        let review = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Review)
            .count() as u32;
        let complete = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Complete)
            .count() as u32;
        let blocked = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Blocked)
            .count() as u32;
        let escalated = self
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Escalated)
            .count() as u32;
        let percent_complete = if total > 0 {
            (complete as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        // Per-phase stats
        let mut phase_map: std::collections::BTreeMap<u32, (String, u32, u32)> =
            std::collections::BTreeMap::new();
        for t in &self.tasks {
            let entry = phase_map
                .entry(t.phase)
                .or_insert_with(|| (t.phase_name.clone(), 0, 0));
            entry.1 += 1;
            if t.status == TaskStatus::Complete {
                entry.2 += 1;
            }
        }
        let phases: Vec<PhaseStats> = phase_map
            .into_iter()
            .map(|(phase, (name, tot, comp))| PhaseStats {
                phase,
                name,
                total: tot,
                complete: comp,
                percent: if tot > 0 {
                    (comp as f64 / tot as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        ForgeStats {
            total,
            queued,
            assigned,
            in_progress,
            review,
            complete,
            blocked,
            escalated,
            percent_complete,
            phases,
        }
    }
}

#[allow(clippy::too_many_lines, unused_assignments)]
fn build_zerodentity_tasks() -> Vec<ForgeTask> {
    let mut tasks = Vec::new();
    let mut id = 1u32;

    macro_rules! task {
        ($phase:expr, $phase_name:expr, $title:expr, $desc:expr, $section:expr, $dep:expr) => {{
            tasks.push(ForgeTask {
                id,
                phase: $phase,
                phase_name: $phase_name.into(),
                title: $title.into(),
                description: $desc.into(),
                spec_section: $section.into(),
                status: TaskStatus::Queued,
                agent: None,
                escalation: EscalationLevel::None,
                depends_on_phase: $dep,
                started_ms: None,
                completed_ms: None,
            });
            id += 1;
        }};
    }

    // Phase 1: Foundation Types (§2)
    task!(
        1,
        "Foundation Types",
        "IdentityClaim + ClaimType + ClaimStatus",
        "Create core identity claim types with 18 ClaimType variants and ClaimStatus enum",
        "§2.2",
        None
    );
    task!(
        1,
        "Foundation Types",
        "ZerodentityScore + PolarAxes",
        "Create the 8-axis polar decomposition score struct with composite and symmetry fields",
        "§2.2",
        None
    );
    task!(
        1,
        "Foundation Types",
        "DeviceFingerprint + FingerprintSignal",
        "Create device fingerprint composite type with 15 FingerprintSignal variants",
        "§2.2",
        None
    );
    task!(
        1,
        "Foundation Types",
        "BehavioralSample + BehavioralSignalType",
        "Create behavioral biometric sample types with 5 signal type variants",
        "§2.2",
        None
    );
    task!(
        1,
        "Foundation Types",
        "OtpChallenge + OtpChannel + OtpState",
        "Create OTP verification state machine types",
        "§2.2",
        None
    );

    // Phase 2: Persistence (§9)
    task!(
        2,
        "Persistence Layer",
        "SQLite schema + migrations",
        "Create 7 new tables: identity_claims, device_fingerprints, behavioral_samples, score_snapshots, otp_challenges, peer_attestations, identity_sessions",
        "§9.1",
        Some(1)
    );
    task!(
        2,
        "Persistence Layer",
        "CRUD operations for all tables",
        "Implement insert/query/update/delete for each 0dentity table on SqliteDagStore",
        "§9.1",
        Some(1)
    );

    // Phase 3: Scoring Engine (§5)
    task!(
        3,
        "Scoring Engine",
        "score_communication()",
        "Email=35, Phone=37, both-bonus=15, extra channels capped at 13. Returns 0-100",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_credential_depth()",
        "DisplayName=5, GovID=35, BiometricLiveness=30, ProfessionalCred=10 each (cap 30)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_device_trust()",
        "Base=20, signal coverage (25 max), consistency score (40 max), multi-session bonus (15)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_behavioral()",
        "Base=10, signal diversity (18 max), baseline similarity (40 max), volume logarithmic (16)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_network_reputation()",
        "Attestations=5 each (cap 40), delegations=8 each (cap 24), challenges=12 each (cap 36)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_temporal_stability()",
        "Age logarithmic (cap 35), verification freshness ratio (30), renewals (20), sessions (15)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_cryptographic_strength()",
        "Base=15, Ed25519=25/Hybrid=40/PQ=35, rotations=8 each (cap 24), entropy=10, stale key penalty",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "score_constitutional_standing()",
        "Base=10, votes=4 each (cap 20), proposals=7 each (cap 21), validator=5 each (cap 25), challenges=8 each (cap 24)",
        "§5.2",
        Some(1)
    );
    task!(
        3,
        "Scoring Engine",
        "Composite + symmetry computation",
        "Unweighted mean of 8 axes. Symmetry = 1 - (σ/μ). ZerodentityScore::compute() entry point",
        "§5.3-§5.4",
        Some(1)
    );

    // Phase 4: Signal Collection (§3)
    task!(
        4,
        "Signal Collection",
        "Client-side hashing protocol",
        "BLAKE3 hash-then-discard pipeline: collect → hash → store hash → zero raw → composite",
        "§3.3",
        None
    );
    task!(
        4,
        "Signal Collection",
        "Fingerprint signal collectors (JS)",
        "15 JavaScript collectors: Canvas, WebGL, Screen, Timezone, UserAgent, Audio, Fonts, Battery, Hardware, Memory, WebRTC, Touch, Platform, DNT, ColorDepth",
        "§3.4",
        None
    );
    task!(
        4,
        "Signal Collection",
        "Behavioral biometric collector (JS)",
        "BehavioralCollector class: keystroke dynamics (μs), mouse velocity, touch pressure, scroll, form navigation cadence. Histogram quantization + stddev",
        "§3.5",
        None
    );

    // Phase 5: Onboarding API (§4 + §7)
    task!(
        5,
        "Onboarding API",
        "POST /claims — create identity claim",
        "First claim creates DID + session token. Validates claim_hash format, stores in DAG, emits TrustReceipt. Dispatches OTP if verification_channel set",
        "§7.1",
        Some(2)
    );
    task!(
        5,
        "Onboarding API",
        "POST /verify — OTP verification",
        "HMAC comparison, attempt counting, TTL check, lockout. On success: emit VerifiedEmail/VerifiedPhone receipt, update score",
        "§7.1",
        Some(2)
    );
    task!(
        5,
        "Onboarding API",
        "POST /verify/resend — resend OTP",
        "60-second cooldown, new challenge_id, preserve attempt count across resends",
        "§7.1",
        Some(2)
    );
    task!(
        5,
        "Onboarding API",
        "GET /server-key — RSA-OAEP public key",
        "Serve 4096-bit RSA-OAEP public key PEM for channel address encryption. Include key_hash for pinning",
        "§7.3",
        None
    );

    // Phase 6: Identity API (§7)
    task!(
        6,
        "Identity API",
        "GET /score — retrieve 0dentity score",
        "Public endpoint (constitutional transparency). Returns full PolarAxes, composite, symmetry, claim_count",
        "§7.2",
        Some(3)
    );
    task!(
        6,
        "Identity API",
        "GET /claims — list claims with filters",
        "Owner-only (bearer token). Filter by status, type. Pagination via limit/offset",
        "§7.2",
        Some(2)
    );
    task!(
        6,
        "Identity API",
        "GET /score/history — score timeline",
        "Public. Query by time range + resolution (daily/weekly/monthly). Returns score snapshots array",
        "§7.2",
        Some(2)
    );
    task!(
        6,
        "Identity API",
        "GET /fingerprints — consistency timeline",
        "Owner-only. Returns composite_hash, captured_ms, consistency_score, signal_count per session",
        "§7.2",
        Some(2)
    );
    task!(
        6,
        "Identity API",
        "POST /attest — peer attestation",
        "Create attestation from verified DID to target DID. Reject self-attestation, duplicate. Compute score impact",
        "§7.2",
        Some(5)
    );
    task!(
        6,
        "Identity API",
        "DELETE /:did — right to erasure",
        "Revoke sessions, mark claims Revoked, zero score snapshots, tombstone DAG nodes, emit erasure receipt",
        "§11.4",
        Some(5)
    );

    // Phase 7: Onboarding UI (§4)
    task!(
        7,
        "Onboarding UI",
        "Landing page + onboarding shell",
        "Self-contained HTML at /0dentity. Dark theme, progress indicator, CTA 'Begin your proof'",
        "§4.1",
        Some(4)
    );
    task!(
        7,
        "Onboarding UI",
        "Name input step",
        "Form with name field, BLAKE3 client-hash, Ed25519 session key generation, behavioral capture, mini polar graph",
        "§4.2",
        Some(4)
    );
    task!(
        7,
        "Onboarding UI",
        "Email input + OTP steps",
        "Email form → RSA-OAEP encrypt → dispatch OTP. 6-digit auto-advance input, countdown timer, resend cooldown",
        "§4.3-§4.4",
        Some(4)
    );
    task!(
        7,
        "Onboarding UI",
        "Phone input + OTP steps",
        "Country picker, E.164 format, SMS OTP with 3-min TTL, metadata disclosure table on completion",
        "§4.5-§4.6",
        Some(4)
    );
    task!(
        7,
        "Onboarding UI",
        "Score reveal with animated polar graph",
        "Full-bleed animated radar graph, sequential axis animation (200ms each), composite counter, 'View My Dashboard' CTA",
        "§4.7",
        Some(8)
    );

    // Phase 8: Polar Graph Renderer (§6)
    task!(
        8,
        "Polar Graph",
        "SVG radar chart renderer",
        "PolarGraph class: 8-axis SVG with concentric grid rings, axis labels, max polygon outline, score polygon fill, vertex dots",
        "§6.1",
        None
    );
    task!(
        8,
        "Polar Graph",
        "Animation engine",
        "animateTo() with cubic ease-in-out, per-axis interpolation, requestAnimationFrame loop, configurable duration",
        "§6.1",
        None
    );
    task!(
        8,
        "Polar Graph",
        "Interactive behaviors",
        "Hover axis → tooltip with score + contributing claims. Click axis → detail panel. Hover polygon → composite + symmetry. Responsive breakpoints",
        "§6.1",
        None
    );

    // Phase 9: Dashboard (§8)
    task!(
        9,
        "Dashboard",
        "Dashboard layout + structure",
        "Self-contained HTML at /0dentity/dashboard. Grid layout: polar graph | score breakdown | claims | history | growth | fingerprints",
        "§8.1-§8.2",
        Some(8)
    );
    task!(
        9,
        "Dashboard",
        "Polar graph integration",
        "Embed PolarGraph instance, poll /score every 5s, animate to new values on change",
        "§8.3-§8.4",
        Some(8)
    );
    task!(
        9,
        "Dashboard",
        "Claims table",
        "Sortable table: type, hash (truncated), status (colored badge), verified timestamp (relative), expiry. Click for detail",
        "§8.2",
        Some(6)
    );
    task!(
        9,
        "Dashboard",
        "Score history sparkline",
        "Inline SVG sparkline showing composite score over time. Poll /score/history with daily resolution",
        "§8.2",
        Some(6)
    );
    task!(
        9,
        "Dashboard",
        "Growth actions panel",
        "Four action cards: Add Gov ID (+35 cred), Request Attestation (+5 network), Cast Vote (+4 constitutional), Rotate Key (+8 crypto). Each links to relevant flow",
        "§8.5",
        Some(6)
    );
    task!(
        9,
        "Dashboard",
        "Fingerprint consistency panel",
        "Session-over-session consistency bars. Poll /fingerprints endpoint. Show composite hash (truncated) per session",
        "§8.2",
        Some(6)
    );

    // Phase 10: ExoChain Integration (§10)
    task!(
        10,
        "Integration",
        "Claim → DAG node pipeline",
        "Every IdentityClaim creates a DagNode: CBOR-encode claim, BLAKE3 hash, link to DAG tips, sign with session key, store.put()",
        "§10.1",
        Some(5)
    );
    task!(
        10,
        "Integration",
        "Verification → TrustReceipt emission",
        "On OTP success: TrustReceipt with action_type 'claim_verified:<type>', outcome Executed, authority chain hash",
        "§10.2",
        Some(5)
    );
    task!(
        10,
        "Integration",
        "Passport API extension",
        "Add zerodentity_score: Option<ZerodentityScore> to PassportResponse. Populate from latest score snapshot",
        "§10.3",
        Some(6)
    );
    task!(
        10,
        "Integration",
        "Sentinel checks: ScoreIntegrity + OtpCleanup",
        "ScoreIntegrity: random DID recomputation ε=0.001. OtpCleanup: expired challenges state != Pending",
        "§10.4",
        Some(3)
    );
    task!(
        10,
        "Integration",
        "Telegram adjutant commands",
        "/0dentity <did> summary, /0dentity-alerts anomalies, inline button [View Full Score]",
        "§10.5",
        Some(6)
    );

    // Phase 11: Test Suite (§12)
    task!(
        11,
        "Test Suite",
        "Type serialization roundtrip tests",
        "Serde roundtrip for every 0dentity type. ClaimType equality. ClaimStatus transition validity",
        "§12.2",
        Some(1)
    );
    task!(
        11,
        "Test Suite",
        "Scoring engine determinism tests",
        "Same claims → same score. Each axis: zero/minimal/maximal claims. Composite arithmetic. Symmetry for uniform/skewed/zero",
        "§12.2",
        Some(3)
    );
    task!(
        11,
        "Test Suite",
        "API endpoint integration tests",
        "POST /claims creates DID. POST /verify success/failure/expiry/lockout. GET /score found/404. GET /claims with filters",
        "§12.2",
        Some(6)
    );
    task!(
        11,
        "Test Suite",
        "Store + migration tests",
        "CRUD all tables. Index usage. Migration idempotency. Schema version check",
        "§12.2",
        Some(2)
    );
    task!(
        11,
        "Test Suite",
        "Fingerprint + behavioral tests",
        "Consistency: identical=1.0, different=0.0, partial=intermediate. Histogram quantization. Empty sample handling",
        "§12.2",
        Some(4)
    );

    // Phase 12: Operational Readiness (§13)
    task!(
        12,
        "Ops Readiness",
        "Environment variable configuration",
        "17 env vars: ZERODENTITY_ENABLED, OTP TTLs, snapshot interval, SMTP config, SMS provider config",
        "§13.1",
        Some(5)
    );
    task!(
        12,
        "Ops Readiness",
        "Prometheus metrics integration",
        "Counters: claims_total, otp_verifications_total. Histogram: score_composite. Gauge: fingerprint_consistency_avg, onboarding_completion_rate",
        "§13.2",
        Some(10)
    );
    task!(
        12,
        "Ops Readiness",
        "main.rs wiring + startup",
        "Module declaration, ZerodentityState construction, router merge, schema migration on startup, config loading",
        "§10.6",
        Some(10)
    );

    tasks
}

// ─── API Handlers ───────────────────────────────────────────────────

/// `GET /api/v1/forge/tasks` — list all spec tasks with current stats.
async fn list_tasks(
    State(state): State<SharedForgeState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in list_tasks");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(serde_json::json!({
        "spec_name": s.spec_name,
        "tasks": s.tasks,
        "stats": s.stats(),
    })))
}

/// `GET /api/v1/forge/stats` — aggregate task statistics.
async fn get_stats(State(state): State<SharedForgeState>) -> Result<Json<ForgeStats>, StatusCode> {
    let s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in get_stats");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(s.stats()))
}

/// `GET /api/v1/forge/activity` — recent task activity log.
async fn get_activity(
    State(state): State<SharedForgeState>,
) -> Result<Json<Vec<ActivityEntry>>, StatusCode> {
    let s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in get_activity");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(s.activity_log.clone()))
}

/// `PUT /api/v1/forge/tasks/:id/status` — update a task's status.
async fn update_task_status(
    State(state): State<SharedForgeState>,
    Path(task_id): Path<u32>,
    Json(body): Json<StatusUpdate>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in update_task_status");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let task = s
        .tasks
        .iter_mut()
        .find(|t| t.id == task_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let old_status = task.status.clone();
    let task_title = task.title.clone();
    task.status = body.status.clone();

    if body.status == TaskStatus::InProgress && task.started_ms.is_none() {
        task.started_ms = Some(now_ms());
    }
    if body.status == TaskStatus::Complete {
        task.completed_ms = Some(now_ms());
    }

    s.activity_log.push(ActivityEntry {
        timestamp_ms: now_ms(),
        message: format!(
            "Task #{} '{}' status: {:?} → {:?}",
            task_id, task_title, old_status, body.status
        ),
        task_id: Some(task_id),
    });

    Ok(Json(serde_json::json!({ "ok": true, "task_id": task_id })))
}

/// `PUT /api/v1/forge/tasks/:id/assign` — assign an agent to a task.
async fn assign_agent(
    State(state): State<SharedForgeState>,
    Path(task_id): Path<u32>,
    Json(body): Json<AgentAssignment>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in assign_agent");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let task = s
        .tasks
        .iter_mut()
        .find(|t| t.id == task_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let task_title = task.title.clone();
    task.agent = Some(body.agent.clone());
    if task.status == TaskStatus::Queued {
        task.status = TaskStatus::Assigned;
    }

    s.activity_log.push(ActivityEntry {
        timestamp_ms: now_ms(),
        message: format!(
            "Task #{} '{}' assigned to {}",
            task_id, task_title, body.agent
        ),
        task_id: Some(task_id),
    });

    Ok(Json(
        serde_json::json!({ "ok": true, "task_id": task_id, "agent": body.agent }),
    ))
}

/// `POST /api/v1/forge/tasks/:id/escalate` — escalate a blocked task.
async fn escalate_task(
    State(state): State<SharedForgeState>,
    Path(task_id): Path<u32>,
    Json(body): Json<EscalateRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in escalate_task");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let task = s
        .tasks
        .iter_mut()
        .find(|t| t.id == task_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    task.escalation = body.level.clone();
    task.status = TaskStatus::Escalated;

    let level_str = match &body.level {
        EscalationLevel::None => "None",
        EscalationLevel::Council => "Council",
        EscalationLevel::AiIrb => "AI-IRB",
        EscalationLevel::Human => "Human Operator",
    };

    s.activity_log.push(ActivityEntry {
        timestamp_ms: now_ms(),
        message: format!(
            "Task #{} ESCALATED to {} — {}",
            task_id, level_str, body.reason
        ),
        task_id: Some(task_id),
    });

    Ok(Json(
        serde_json::json!({ "ok": true, "task_id": task_id, "escalation": level_str }),
    ))
}

/// `POST /api/v1/forge/log` — append an entry to the activity log.
async fn append_log(
    State(state): State<SharedForgeState>,
    Json(body): Json<LogEntry>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in append_log");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    s.activity_log.push(ActivityEntry {
        timestamp_ms: now_ms(),
        message: body.message,
        task_id: body.task_id,
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Dashboard HTML ─────────────────────────────────────────────────

/// `GET /exoforge` — serve the ExoForge task-board dashboard as HTML.
async fn serve_dashboard(
    State(state): State<SharedForgeState>,
) -> Result<Html<String>, StatusCode> {
    let s = state.lock().map_err(|_| {
        tracing::error!("ForgeState mutex poisoned in serve_dashboard");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let tasks_json = serde_json::to_string(&s.tasks).unwrap_or_default();
    let stats_json = serde_json::to_string(&s.stats()).unwrap_or_default();
    let log_json = serde_json::to_string(&s.activity_log).unwrap_or_default();
    drop(s);

    Ok(Html(format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ExoForge — Build Orchestration</title>
<style>
:root {{
  --bg-void: #050810;
  --bg-primary: #0a0e17;
  --bg-card: #111827;
  --bg-elevated: #1e293b;
  --bg-hover: #263049;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent: #38bdf8;
  --accent-dim: rgba(56,189,248,0.12);
  --green: #22c55e;
  --amber: #f59e0b;
  --red: #ef4444;
  --purple: #a855f7;
  --orange: #f97316;
  --blue: #3b82f6;
  --slate: #475569;
  --border: rgba(148,163,184,0.08);
  --radius: 8px;
  --font-mono: ui-monospace,'Cascadia Code','Fira Code',Menlo,Consolas,monospace;
  --font-sans: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}}
*{{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  background: var(--bg-void);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  min-height: 100vh;
}}

/* Header */
.header {{
  background: var(--bg-primary);
  border-bottom: 1px solid var(--border);
  padding: 16px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
  backdrop-filter: blur(12px);
}}
.header-left {{
  display: flex;
  align-items: center;
  gap: 16px;
}}
.logo {{
  font-family: var(--font-mono);
  font-size: 20px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 2px;
}}
.logo span {{ color: var(--text-muted); font-weight: 400; }}
.spec-badge {{
  background: var(--accent-dim);
  color: var(--accent);
  padding: 4px 12px;
  border-radius: 12px;
  font-family: var(--font-mono);
  font-size: 12px;
  border: 1px solid rgba(56,189,248,0.2);
}}
.header-right {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.progress-ring {{
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 700;
  color: var(--accent);
}}
.progress-label {{
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 1px;
}}

/* Stats row */
.stats-row {{
  display: flex;
  gap: 12px;
  padding: 20px 24px;
  background: var(--bg-primary);
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}}
.stat-card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 20px;
  flex: 1;
  min-width: 100px;
  text-align: center;
}}
.stat-value {{
  font-family: var(--font-mono);
  font-size: 28px;
  font-weight: 700;
  line-height: 1.2;
}}
.stat-label {{
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  margin-top: 2px;
}}

/* Progress bar */
.progress-bar-container {{
  padding: 0 24px 16px;
  background: var(--bg-primary);
  border-bottom: 1px solid var(--border);
}}
.progress-bar {{
  height: 6px;
  background: var(--bg-elevated);
  border-radius: 3px;
  overflow: hidden;
}}
.progress-fill {{
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--green));
  border-radius: 3px;
  transition: width 0.8s ease;
}}

/* Main content */
.content {{
  display: grid;
  grid-template-columns: 1fr 360px;
  gap: 0;
  min-height: calc(100vh - 200px);
}}

/* Phases column */
.phases-column {{
  padding: 16px 24px;
  overflow-y: auto;
  border-right: 1px solid var(--border);
}}
.phase {{
  margin-bottom: 16px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}}
.phase-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: var(--bg-elevated);
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}}
.phase-header:hover {{ background: var(--bg-hover); }}
.phase-title {{
  font-weight: 600;
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 8px;
}}
.phase-title .chevron {{
  color: var(--text-muted);
  transition: transform 0.2s;
  font-size: 12px;
}}
.phase.collapsed .chevron {{ transform: rotate(-90deg); }}
.phase.collapsed .phase-tasks {{ display: none; }}
.phase-progress {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
}}
.phase-bar {{
  width: 80px;
  height: 4px;
  background: var(--bg-card);
  border-radius: 2px;
  overflow: hidden;
}}
.phase-bar-fill {{
  height: 100%;
  background: var(--accent);
  transition: width 0.5s ease;
}}

/* Tasks */
.task {{
  display: grid;
  grid-template-columns: 32px 1fr auto auto auto;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  border-top: 1px solid var(--border);
  transition: background 0.15s;
}}
.task:hover {{ background: rgba(56,189,248,0.03); }}
.task-id {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  text-align: center;
}}
.task-info {{
  min-width: 0;
}}
.task-title {{
  font-weight: 500;
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.task-desc {{
  font-size: 11px;
  color: var(--text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-top: 1px;
}}
.task-agent {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
  white-space: nowrap;
}}
.task-section {{
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-elevated);
  padding: 2px 8px;
  border-radius: 4px;
  white-space: nowrap;
}}

/* Status badges */
.status {{
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  white-space: nowrap;
}}
.status-Queued {{ background: rgba(71,85,105,0.2); color: var(--slate); }}
.status-Assigned {{ background: rgba(59,130,246,0.15); color: var(--blue); }}
.status-InProgress {{ background: rgba(245,158,11,0.15); color: var(--amber); }}
.status-Review {{ background: rgba(168,85,247,0.15); color: var(--purple); }}
.status-Complete {{ background: rgba(34,197,94,0.15); color: var(--green); }}
.status-Blocked {{ background: rgba(239,68,68,0.15); color: var(--red); }}
.status-Escalated {{ background: rgba(249,115,22,0.15); color: var(--orange); }}

/* Escalation indicator */
.escalation {{
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 4px;
  text-transform: uppercase;
}}
.esc-Council {{ background: rgba(168,85,247,0.2); color: var(--purple); }}
.esc-AiIrb {{ background: rgba(249,115,22,0.2); color: var(--orange); }}
.esc-Human {{ background: rgba(239,68,68,0.2); color: var(--red); }}

/* Activity log */
.log-column {{
  background: var(--bg-card);
  border-left: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}}
.log-header {{
  padding: 12px 16px;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 6px;
}}
.log-header .dot {{
  width: 6px; height: 6px;
  background: var(--green);
  border-radius: 50%;
  animation: pulse 2s infinite;
}}
@keyframes pulse {{
  0%, 100% {{ opacity: 1; }}
  50% {{ opacity: 0.3; }}
}}
.log-entries {{
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
}}
.log-entry {{
  padding: 6px 16px;
  font-size: 12px;
  border-bottom: 1px solid var(--border);
  line-height: 1.4;
}}
.log-entry:hover {{ background: var(--bg-hover); }}
.log-time {{
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-muted);
  margin-right: 8px;
}}
.log-task-ref {{
  font-family: var(--font-mono);
  color: var(--accent);
  font-weight: 600;
}}

/* Responsive */
@media (max-width: 900px) {{
  .content {{ grid-template-columns: 1fr; }}
  .log-column {{ max-height: 300px; }}
  .stats-row {{ gap: 8px; }}
  .stat-card {{ min-width: 70px; padding: 8px 12px; }}
  .stat-value {{ font-size: 22px; }}
}}

/* Scrollbar */
::-webkit-scrollbar {{ width: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--bg-elevated); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--slate); }}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div class="logo">EXOFORGE <span>v1</span></div>
    <div class="spec-badge" id="spec-badge">0DENTITY-APP-SPEC.md</div>
  </div>
  <div class="header-right">
    <div>
      <div class="progress-ring" id="progress-pct">0%</div>
      <div class="progress-label">complete</div>
    </div>
  </div>
</div>

<div class="stats-row" id="stats-row"></div>

<div class="progress-bar-container">
  <div class="progress-bar">
    <div class="progress-fill" id="progress-fill" style="width:0%"></div>
  </div>
</div>

<div class="content">
  <div class="phases-column" id="phases-column"></div>
  <div class="log-column">
    <div class="log-header"><span class="dot"></span> Activity Feed</div>
    <div class="log-entries" id="log-entries"></div>
  </div>
</div>

<script>
// Initial data from server-side render
let tasks = {tasks_json};
let stats = {stats_json};
let activityLog = {log_json};

const statusOrder = ['Escalated','Blocked','InProgress','Review','Assigned','Queued','Complete'];
const statusIcons = {{
  Queued: '\u23F3', Assigned: '\uD83D\uDCCB', InProgress: '\u2699\uFE0F',
  Review: '\uD83D\uDD0D', Complete: '\u2705', Blocked: '\uD83D\uDEAB', Escalated: '\u26A0\uFE0F'
}};

function renderStats() {{
  const row = document.getElementById('stats-row');
  const items = [
    ['total', stats.total, '--text-primary'],
    ['queued', stats.queued, '--slate'],
    ['assigned', stats.assigned, '--blue'],
    ['active', stats.in_progress, '--amber'],
    ['review', stats.review, '--purple'],
    ['done', stats.complete, '--green'],
    ['blocked', stats.blocked, '--red'],
    ['escalated', stats.escalated, '--orange'],
  ];
  row.innerHTML = items.map(([label, value, color]) =>
    `<div class="stat-card">
      <div class="stat-value" style="color:var(${{color}})">${{value}}</div>
      <div class="stat-label">${{label}}</div>
    </div>`
  ).join('');

  document.getElementById('progress-pct').textContent =
    stats.percent_complete.toFixed(0) + '%';
  document.getElementById('progress-fill').style.width =
    stats.percent_complete.toFixed(1) + '%';
}}

function renderPhases() {{
  const col = document.getElementById('phases-column');
  // Group tasks by phase
  const phases = {{}};
  tasks.forEach(t => {{
    if (!phases[t.phase]) phases[t.phase] = {{ name: t.phase_name, tasks: [] }};
    phases[t.phase].tasks.push(t);
  }});

  col.innerHTML = Object.entries(phases).map(([phaseNum, phase]) => {{
    const done = phase.tasks.filter(t => t.status === 'Complete').length;
    const total = phase.tasks.length;
    const pct = total > 0 ? (done / total * 100).toFixed(0) : 0;
    const allDone = done === total;

    return `<div class="phase ${{allDone ? '' : ''}}">
      <div class="phase-header" onclick="this.parentElement.classList.toggle('collapsed')">
        <div class="phase-title">
          <span class="chevron">\u25BC</span>
          Phase ${{phaseNum}}: ${{phase.name}}
        </div>
        <div class="phase-progress">
          <span>${{done}}/${{total}}</span>
          <div class="phase-bar"><div class="phase-bar-fill" style="width:${{pct}}%"></div></div>
          <span>${{pct}}%</span>
        </div>
      </div>
      <div class="phase-tasks">
        ${{phase.tasks.map(t => `
          <div class="task" data-task-id="${{t.id}}">
            <div class="task-id">#${{t.id}}</div>
            <div class="task-info">
              <div class="task-title">${{t.title}}</div>
              <div class="task-desc">${{t.description}}</div>
            </div>
            <div class="task-agent">${{t.agent || '\u2014'}}</div>
            <span class="status status-${{t.status}}">${{statusIcons[t.status] || ''}} ${{t.status}}</span>
            <div class="task-section">${{t.spec_section}}</div>
          </div>
        `).join('')}}
      </div>
    </div>`;
  }}).join('');
}}

function renderLog() {{
  const container = document.getElementById('log-entries');
  // Show newest first
  const entries = [...activityLog].reverse();
  container.innerHTML = entries.map(e => {{
    const d = new Date(e.timestamp_ms);
    const time = d.toLocaleTimeString('en-US', {{ hour12: false }});
    const taskRef = e.task_id ? `<span class="log-task-ref">#${{e.task_id}}</span> ` : '';
    return `<div class="log-entry"><span class="log-time">${{time}}</span>${{taskRef}}${{e.message}}</div>`;
  }}).join('');
}}

function render() {{
  renderStats();
  renderPhases();
  renderLog();
}}

// Initial render
render();

// Poll for updates every 3 seconds
setInterval(async () => {{
  try {{
    const resp = await fetch('/api/v1/forge/tasks');
    if (resp.ok) {{
      const data = await resp.json();
      tasks = data.tasks;
      stats = data.stats;
    }}
    const logResp = await fetch('/api/v1/forge/activity');
    if (logResp.ok) {{
      activityLog = await logResp.json();
    }}
    render();
  }} catch (e) {{
    console.warn('ExoForge poll failed:', e.message);
    const hdr = document.querySelector('.forge-header');
    if (hdr) hdr.style.borderBottom = '2px solid #ef4444';
    setTimeout(() => {{ if (hdr) hdr.style.borderBottom = ''; }}, 2000);
  }}
}}, 3000);
</script>

</body>
</html>"##
    )))
}

// ─── Router ─────────────────────────────────────────────────────────

/// Build the Axum router for all ExoForge API and dashboard routes.
pub fn exoforge_router(state: SharedForgeState) -> Router {
    Router::new()
        .route("/exoforge", get(serve_dashboard))
        .route("/api/v1/forge/tasks", get(list_tasks))
        .route("/api/v1/forge/stats", get(get_stats))
        .route("/api/v1/forge/activity", get(get_activity))
        .route("/api/v1/forge/tasks/:id/status", post(update_task_status))
        .route("/api/v1/forge/tasks/:id/assign", post(assign_agent))
        .route("/api/v1/forge/tasks/:id/escalate", post(escalate_task))
        .route("/api/v1/forge/log", post(append_log))
        .with_state(state)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn task_initialization_produces_56_tasks() {
        let tasks = build_zerodentity_tasks();
        assert_eq!(tasks.len(), 56);
        // All start as Queued
        assert!(tasks.iter().all(|t| t.status == TaskStatus::Queued));
        // All have unique IDs
        let ids: std::collections::HashSet<u32> = tasks.iter().map(|t| t.id).collect();
        assert_eq!(ids.len(), 56);
    }

    #[test]
    fn phase_coverage() {
        let tasks = build_zerodentity_tasks();
        let phases: std::collections::BTreeSet<u32> = tasks.iter().map(|t| t.phase).collect();
        // 12 phases
        assert_eq!(phases.len(), 12);
        assert_eq!(*phases.iter().next().unwrap(), 1);
        assert_eq!(*phases.iter().last().unwrap(), 12);
    }

    #[test]
    fn stats_computation() {
        let mut state = ForgeState::new_zerodentity();
        let s = state.stats();
        assert_eq!(s.total, 56);
        assert_eq!(s.queued, 56);
        assert_eq!(s.complete, 0);
        assert!((s.percent_complete - 0.0).abs() < 0.001);

        // Complete one task
        state.tasks[0].status = TaskStatus::Complete;
        let s2 = state.stats();
        assert_eq!(s2.complete, 1);
        assert!(s2.percent_complete > 1.0);
    }

    #[test]
    fn state_initialization() {
        let state = ForgeState::new_zerodentity();
        assert_eq!(state.spec_name, "0DENTITY-APP-SPEC.md");
        assert_eq!(state.activity_log.len(), 3);
    }

    #[tokio::test]
    async fn dashboard_returns_html() {
        let state: SharedForgeState = Arc::new(Mutex::new(ForgeState::new_zerodentity()));
        let router = exoforge_router(state);

        let req = axum::http::Request::builder()
            .uri("/exoforge")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("EXOFORGE"));
        assert!(html.contains("0DENTITY-APP-SPEC.md"));
        assert!(html.contains("Foundation Types"));
        assert!(html.contains("Activity Feed"));
    }

    #[tokio::test]
    async fn tasks_api_returns_all_tasks() {
        let state: SharedForgeState = Arc::new(Mutex::new(ForgeState::new_zerodentity()));
        let router = exoforge_router(state);

        let req = axum::http::Request::builder()
            .uri("/api/v1/forge/tasks")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["stats"]["total"], 56);
    }
}
