//! Read-only DAG DB benchmark isolation and diagnostic browser contracts.

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable browser view model schema version.
pub const DIAGNOSTIC_BROWSER_SCHEMA_VERSION: &str = "dagdb_diagnostic_browser_v1";
/// Missing diagnostic report message shown by the browser.
pub const MISSING_REPORT_MESSAGE: &str =
    "Diagnostic reports not found. Run the deterministic diagnostic benchmark first.";
/// Malformed diagnostic report message shown by the browser.
pub const MALFORMED_REPORT_MESSAGE: &str =
    "Diagnostic report artifact is malformed. Re-run the deterministic diagnostic benchmark.";
/// Graph unavailable message shown by the browser.
pub const GRAPH_UNAVAILABLE_MESSAGE: &str = "Graph data not available for this silo yet.";
/// Local browser safety badge text.
pub const LOCAL_BROWSER_BADGE: &str =
    "Local deterministic diagnostic browser. Not a production DB browser.";
/// Deterministic harness warning shown in the overview.
pub const HARNESS_TRUTH_WARNING: &str = "This dashboard displays deterministic EXOCHAIN benchmark harness results. It does not prove live external model performance, real API dollar savings, or real user productivity until a separately approved live/replay benchmark is run.";

const SUMMARY_JSON: &str = "summary.json";
const SUMMARY_MD: &str = "summary.md";
const PER_TASK_RESULTS_JSON: &str = "per_task_results.json";
const LATENCY_BREAKDOWN_JSON: &str = "latency_breakdown.json";
const COST_BREAKDOWN_JSON: &str = "cost_breakdown.json";
const QUALITY_BREAKDOWN_JSON: &str = "quality_breakdown.json";
const RECOMMENDATIONS_MD: &str = "recommendations.md";

/// Browser database role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseRole {
    /// Main production DB role.
    Main,
    /// Control benchmark DB role.
    ControlBenchmark,
    /// Governed benchmark DB role.
    GovernedBenchmark,
}

/// Browser-facing benchmark DB config. This never stores raw DB URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkDatabaseConfig {
    pub role: DatabaseRole,
    pub database_url_env: String,
    pub tenant_id: String,
    pub namespace: String,
    pub read_only: bool,
    pub allow_benchmark_writes: bool,
    pub allow_synthetic_data: bool,
    pub real_private_data_access_allowed: bool,
    pub graph_routing_enabled: bool,
}

/// Sanitized browser-facing silo status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseSiloStatus {
    pub role: DatabaseRole,
    pub configured: bool,
    pub env_var_name: String,
    pub read_only: bool,
    pub benchmark_writes_allowed: bool,
    pub synthetic_data_allowed: bool,
    pub real_private_data_access_allowed: bool,
    pub graph_routing_enabled: bool,
    pub isolation_status: String,
    pub contamination_risk_status: String,
}

/// Browser view model load failures.
#[derive(Debug, Error)]
pub enum BrowserError {
    /// Diagnostic reports are missing.
    #[error("{message}")]
    MissingReports {
        /// User-facing message.
        message: &'static str,
        /// Missing artifact names.
        missing: Vec<String>,
    },
    /// Diagnostic reports are malformed.
    #[error("{message}: {artifact}")]
    MalformedReport {
        /// User-facing message.
        message: &'static str,
        /// Artifact name.
        artifact: String,
    },
    /// I/O failure while reading an artifact.
    #[error("browser_report_io_failed: {artifact}")]
    Io {
        /// Artifact name.
        artifact: String,
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
    /// JSON failure while reading an artifact.
    #[error("browser_report_json_failed: {artifact}")]
    Json {
        /// Artifact name.
        artifact: String,
        /// Source JSON error.
        #[source]
        source: serde_json::Error,
    },
}

/// Browser overview summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserOverview {
    pub deterministic_mode: bool,
    pub live_model_status: String,
    pub replay_fixture_status: String,
    pub optimized_runner_status: String,
    pub fixture_ids: Vec<String>,
    pub local_browser_badge: String,
    pub truth_warning: String,
}

/// Runner aggregate row for browser tables and bars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserRunnerRollup {
    pub fixture_kind: String,
    pub fixture_id: String,
    pub runner: String,
    pub diagnostic_label: String,
    pub task_count: u64,
    pub total_prompt_tokens: u64,
    pub total_cost_micro_exo: u64,
    pub average_latency_ms: u64,
    pub average_quality_score_bp: u64,
    pub average_citation_accuracy_bp: u64,
    pub average_unsupported_claim_rate_bp: u64,
}

/// Browser comparison row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserComparison {
    pub comparison_name: String,
    pub fixture_kind: String,
    pub neutral_runner: String,
    pub dag_runner: String,
    pub fairness_passed: bool,
    pub cost_savings_claim_allowed: bool,
    pub quality_improvement_claim_allowed: bool,
    pub overall_diagnostic_claim_allowed: bool,
    pub token_reduction_bp: Option<u64>,
    pub cost_reduction_bp: Option<u64>,
    pub quality_delta_bp: i64,
    pub citation_delta_bp: i64,
    pub unsupported_claim_improvement_bp: i64,
    pub latency_delta_ms: i64,
    pub net_savings_micro_exo: i64,
}

/// Per-task browser diagnostic row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserPerTaskResult {
    pub fixture_kind: String,
    pub fixture_id: String,
    pub task_id: String,
    pub task_type: String,
    pub runner: String,
    pub diagnostic_label: String,
    pub prompt_tokens: u64,
    pub total_cost_micro_exo: u64,
    pub latency_ms: u64,
    pub quality_score_bp: u64,
    pub citation_accuracy_bp: u64,
    pub unsupported_claim_rate_bp: u64,
    pub selected_refs: u64,
    pub route_count: u64,
    pub context_packet_tokens: u64,
    pub overall_diagnostic_claim_allowed: bool,
    pub reason_if_disallowed: Option<String>,
}

/// Browser chart point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserSeriesPoint {
    pub fixture_kind: String,
    pub task_id: String,
    pub runner: String,
    pub value: u64,
}

/// Browser chart series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserSeries {
    pub metric: String,
    pub points: Vec<DiagnosticBrowserSeriesPoint>,
}

/// Browser graph node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserGraphNode {
    pub node_id: String,
    pub label: String,
    pub node_kind: String,
    pub graph_style: String,
    pub status: Option<String>,
    pub risk_class: Option<String>,
}

/// Browser graph edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserGraphEdge {
    pub source: String,
    pub target: String,
    pub edge_kind: String,
    pub receipt_id: Option<String>,
}

/// Browser graph view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserGraphView {
    pub silo_role: DatabaseRole,
    pub graph_style: String,
    pub source: String,
    pub availability_status: String,
    pub partial: bool,
    pub nodes: Vec<DiagnosticBrowserGraphNode>,
    pub edges: Vec<DiagnosticBrowserGraphEdge>,
    pub message: String,
}

/// Browser traceability row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserTraceability {
    pub fixture_kind: String,
    pub task_id: String,
    pub runner: String,
    pub selected_refs: u64,
    pub route_count: u64,
    pub context_packet_tokens: u64,
    pub reason_if_disallowed: Option<String>,
}

/// Read-only derived browser view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBrowserViewModel {
    pub schema_version: String,
    pub generated_from: Vec<String>,
    pub database_silos: Vec<DatabaseSiloStatus>,
    pub overview: DiagnosticBrowserOverview,
    pub runner_rollups: Vec<DiagnosticBrowserRunnerRollup>,
    pub comparisons: Vec<DiagnosticBrowserComparison>,
    pub per_task_results: Vec<DiagnosticBrowserPerTaskResult>,
    pub latency_series: Vec<DiagnosticBrowserSeries>,
    pub cost_series: Vec<DiagnosticBrowserSeries>,
    pub quality_series: Vec<DiagnosticBrowserSeries>,
    pub graph_views: Vec<DiagnosticBrowserGraphView>,
    pub traceability: Vec<DiagnosticBrowserTraceability>,
    pub recommendations: Vec<String>,
    pub warnings: Vec<String>,
}

/// Return the locked database configs in stable role order.
#[must_use]
pub fn benchmark_database_configs() -> Vec<BenchmarkDatabaseConfig> {
    vec![
        BenchmarkDatabaseConfig {
            role: DatabaseRole::Main,
            database_url_env: "EXO_DAGDB_MAIN_DATABASE_URL".into(),
            tenant_id: "main".into(),
            namespace: "production".into(),
            read_only: true,
            allow_benchmark_writes: false,
            allow_synthetic_data: false,
            real_private_data_access_allowed: false,
            graph_routing_enabled: true,
        },
        BenchmarkDatabaseConfig {
            role: DatabaseRole::ControlBenchmark,
            database_url_env: "EXO_DAGDB_CONTROL_BENCH_DATABASE_URL".into(),
            tenant_id: "benchmark_control".into(),
            namespace: "control_benchmark".into(),
            read_only: true,
            allow_benchmark_writes: false,
            allow_synthetic_data: true,
            real_private_data_access_allowed: false,
            graph_routing_enabled: false,
        },
        BenchmarkDatabaseConfig {
            role: DatabaseRole::GovernedBenchmark,
            database_url_env: "EXO_DAGDB_GOVERNED_BENCH_DATABASE_URL".into(),
            tenant_id: "benchmark_governed".into(),
            namespace: "governed_benchmark".into(),
            read_only: true,
            allow_benchmark_writes: true,
            allow_synthetic_data: true,
            real_private_data_access_allowed: false,
            graph_routing_enabled: true,
        },
    ]
}

/// Build sanitized silo statuses from an environment lookup closure.
#[must_use]
pub fn database_silo_statuses_from_env<F>(env_lookup: F) -> Vec<DatabaseSiloStatus>
where
    F: Fn(&str) -> Option<String>,
{
    let configs = benchmark_database_configs();
    let configured_count = configs
        .iter()
        .filter(|config| env_lookup(config.database_url_env.as_str()).is_some())
        .count();
    configs
        .into_iter()
        .map(|config| {
            let configured = env_lookup(config.database_url_env.as_str()).is_some();
            let isolation_status = if configured_count == 3 {
                "fully_configured"
            } else {
                "not_fully_configured"
            };
            let contamination_risk_status = contamination_risk_status(&config, configured);
            DatabaseSiloStatus {
                role: config.role,
                configured,
                env_var_name: config.database_url_env,
                read_only: config.read_only,
                benchmark_writes_allowed: config.allow_benchmark_writes,
                synthetic_data_allowed: config.allow_synthetic_data,
                real_private_data_access_allowed: config.real_private_data_access_allowed,
                graph_routing_enabled: config.graph_routing_enabled,
                isolation_status: isolation_status.into(),
                contamination_risk_status,
            }
        })
        .collect()
}

/// Return default sanitized silo statuses using the process environment.
#[must_use]
pub fn database_silo_statuses() -> Vec<DatabaseSiloStatus> {
    database_silo_statuses_from_env(|key| std::env::var(key).ok())
}

/// Build the browser view model from report artifacts in a directory.
pub fn build_diagnostic_browser_view_model(
    report_dir: &Path,
    database_silos: Vec<DatabaseSiloStatus>,
) -> Result<DiagnosticBrowserViewModel, BrowserError> {
    let required_json = [
        SUMMARY_JSON,
        PER_TASK_RESULTS_JSON,
        LATENCY_BREAKDOWN_JSON,
        COST_BREAKDOWN_JSON,
        QUALITY_BREAKDOWN_JSON,
    ];
    let missing = required_json
        .iter()
        .filter(|artifact| !report_dir.join(artifact).is_file())
        .map(|artifact| (*artifact).to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(BrowserError::MissingReports {
            message: MISSING_REPORT_MESSAGE,
            missing,
        });
    }

    let summary = read_json(report_dir, SUMMARY_JSON)?;
    let per_task = read_json(report_dir, PER_TASK_RESULTS_JSON)?;
    let _latency = read_json(report_dir, LATENCY_BREAKDOWN_JSON)?;
    let _cost = read_json(report_dir, COST_BREAKDOWN_JSON)?;
    let _quality = read_json(report_dir, QUALITY_BREAKDOWN_JSON)?;

    require_object(&summary, SUMMARY_JSON)?;
    require_array(
        path_value(&summary, "runner_aggregates", SUMMARY_JSON)?,
        SUMMARY_JSON,
    )?;
    require_array(
        path_value(&summary, "comparisons", SUMMARY_JSON)?,
        SUMMARY_JSON,
    )?;
    require_array(&per_task, PER_TASK_RESULTS_JSON)?;

    let summary_md = read_optional_text(report_dir, SUMMARY_MD);
    let recommendations_md = read_optional_text(report_dir, RECOMMENDATIONS_MD);
    let mut warnings = Vec::new();
    if summary_md.is_err() {
        warnings.push("summary.md unavailable or malformed".into());
    }
    if recommendations_md.is_err() {
        warnings.push("recommendations.md unavailable or malformed".into());
    }

    let per_task_rows = build_per_task_rows(&per_task)?;
    Ok(DiagnosticBrowserViewModel {
        schema_version: DIAGNOSTIC_BROWSER_SCHEMA_VERSION.into(),
        generated_from: generated_from_paths(),
        database_silos,
        overview: build_overview(&summary)?,
        runner_rollups: build_rollups(&summary)?,
        comparisons: build_comparisons(&summary)?,
        latency_series: vec![series_from_rows("latency_ms", &per_task_rows)],
        cost_series: vec![series_from_rows("total_cost_micro_exo", &per_task_rows)],
        quality_series: vec![
            series_from_rows("quality_score_bp", &per_task_rows),
            series_from_rows("citation_accuracy_bp", &per_task_rows),
            series_from_rows("unsupported_claim_rate_bp", &per_task_rows),
            series_from_rows("prompt_tokens", &per_task_rows),
            series_from_rows("selected_refs", &per_task_rows),
            series_from_rows("context_packet_tokens", &per_task_rows),
        ],
        graph_views: unavailable_graph_views(),
        traceability: build_traceability(&per_task_rows),
        recommendations: recommendations_from(&summary, recommendations_md.ok()),
        warnings,
        per_task_results: per_task_rows,
    })
}

fn contamination_risk_status(config: &BenchmarkDatabaseConfig, configured: bool) -> String {
    if !configured {
        return "not_configured".into();
    }
    match config.role {
        DatabaseRole::Main if config.allow_benchmark_writes || config.allow_synthetic_data => {
            "blocked_main_contamination_risk".into()
        }
        DatabaseRole::ControlBenchmark if config.graph_routing_enabled => {
            "blocked_control_graph_routing_risk".into()
        }
        _ => "isolated".into(),
    }
}

fn read_json(report_dir: &Path, artifact: &str) -> Result<Value, BrowserError> {
    let text =
        fs::read_to_string(report_dir.join(artifact)).map_err(|source| BrowserError::Io {
            artifact: artifact.into(),
            source,
        })?;
    serde_json::from_str(&text).map_err(|source| BrowserError::Json {
        artifact: artifact.into(),
        source,
    })
}

fn read_optional_text(report_dir: &Path, artifact: &str) -> Result<String, BrowserError> {
    fs::read_to_string(report_dir.join(artifact)).map_err(|source| BrowserError::Io {
        artifact: artifact.into(),
        source,
    })
}

fn require_object<'a>(
    value: &'a Value,
    artifact: &str,
) -> Result<&'a serde_json::Map<String, Value>, BrowserError> {
    value.as_object().ok_or_else(|| malformed(artifact))
}

fn require_array<'a>(value: &'a Value, artifact: &str) -> Result<&'a [Value], BrowserError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| malformed(artifact))
}

fn path_value<'a>(value: &'a Value, key: &str, artifact: &str) -> Result<&'a Value, BrowserError> {
    require_object(value, artifact)?
        .get(key)
        .ok_or_else(|| malformed(artifact))
}

fn malformed(artifact: &str) -> BrowserError {
    BrowserError::MalformedReport {
        message: MALFORMED_REPORT_MESSAGE,
        artifact: artifact.into(),
    }
}

fn build_overview(summary: &Value) -> Result<DiagnosticBrowserOverview, BrowserError> {
    Ok(DiagnosticBrowserOverview {
        deterministic_mode: bool_field(summary, "deterministic_mode", SUMMARY_JSON)?,
        live_model_status: string_field(summary, "live_model_status", SUMMARY_JSON)?,
        replay_fixture_status: string_field(summary, "replay_fixture_status", SUMMARY_JSON)?,
        optimized_runner_status: string_field(summary, "optimized_runner_status", SUMMARY_JSON)?,
        fixture_ids: string_vec_field(summary, "fixture_ids", SUMMARY_JSON)?,
        local_browser_badge: LOCAL_BROWSER_BADGE.into(),
        truth_warning: HARNESS_TRUTH_WARNING.into(),
    })
}

fn build_rollups(summary: &Value) -> Result<Vec<DiagnosticBrowserRunnerRollup>, BrowserError> {
    require_array(
        path_value(summary, "runner_aggregates", SUMMARY_JSON)?,
        SUMMARY_JSON,
    )?
    .iter()
    .map(|row| {
        Ok(DiagnosticBrowserRunnerRollup {
            fixture_kind: string_field(row, "fixture_kind", SUMMARY_JSON)?,
            fixture_id: string_field(row, "fixture_id", SUMMARY_JSON)?,
            runner: string_field(row, "runner", SUMMARY_JSON)?,
            diagnostic_label: string_field(row, "diagnostic_label", SUMMARY_JSON)?,
            task_count: u64_field(row, "task_count", SUMMARY_JSON)?,
            total_prompt_tokens: u64_field(row, "total_prompt_tokens", SUMMARY_JSON)?,
            total_cost_micro_exo: u64_field(row, "total_cost_micro_exo", SUMMARY_JSON)?,
            average_latency_ms: u64_field(row, "average_latency_ms", SUMMARY_JSON)?,
            average_quality_score_bp: u64_field(row, "average_quality_score_bp", SUMMARY_JSON)?,
            average_citation_accuracy_bp: u64_field(
                row,
                "average_citation_accuracy_bp",
                SUMMARY_JSON,
            )?,
            average_unsupported_claim_rate_bp: u64_field(
                row,
                "average_unsupported_claim_rate_bp",
                SUMMARY_JSON,
            )?,
        })
    })
    .collect()
}

fn build_comparisons(summary: &Value) -> Result<Vec<DiagnosticBrowserComparison>, BrowserError> {
    require_array(
        path_value(summary, "comparisons", SUMMARY_JSON)?,
        SUMMARY_JSON,
    )?
    .iter()
    .map(|row| {
        Ok(DiagnosticBrowserComparison {
            comparison_name: string_field(row, "comparison_name", SUMMARY_JSON)?,
            fixture_kind: string_field(row, "fixture_kind", SUMMARY_JSON)?,
            neutral_runner: string_field(row, "neutral_runner", SUMMARY_JSON)?,
            dag_runner: string_field(row, "dag_runner", SUMMARY_JSON)?,
            fairness_passed: bool_field(row, "fairness_passed", SUMMARY_JSON)?,
            cost_savings_claim_allowed: bool_field(
                row,
                "cost_savings_claim_allowed",
                SUMMARY_JSON,
            )?,
            quality_improvement_claim_allowed: bool_field(
                row,
                "quality_improvement_claim_allowed",
                SUMMARY_JSON,
            )?,
            overall_diagnostic_claim_allowed: bool_field(
                row,
                "overall_diagnostic_claim_allowed",
                SUMMARY_JSON,
            )?,
            token_reduction_bp: optional_u64_field(row, "token_reduction_bp", SUMMARY_JSON)?,
            cost_reduction_bp: optional_u64_field(row, "cost_reduction_bp", SUMMARY_JSON)?,
            quality_delta_bp: i64_field(row, "quality_delta_bp", SUMMARY_JSON)?,
            citation_delta_bp: i64_field(row, "citation_delta_bp", SUMMARY_JSON)?,
            unsupported_claim_improvement_bp: i64_field(
                row,
                "unsupported_claim_improvement_bp",
                SUMMARY_JSON,
            )?,
            latency_delta_ms: i64_field(row, "latency_delta_ms", SUMMARY_JSON)?,
            net_savings_micro_exo: i64_field(row, "net_savings_micro_exo", SUMMARY_JSON)?,
        })
    })
    .collect()
}

fn build_per_task_rows(value: &Value) -> Result<Vec<DiagnosticBrowserPerTaskResult>, BrowserError> {
    require_array(value, PER_TASK_RESULTS_JSON)?
        .iter()
        .map(|row| {
            Ok(DiagnosticBrowserPerTaskResult {
                fixture_kind: string_field(row, "fixture_kind", PER_TASK_RESULTS_JSON)?,
                fixture_id: string_field(row, "fixture_id", PER_TASK_RESULTS_JSON)?,
                task_id: string_field(row, "task_id", PER_TASK_RESULTS_JSON)?,
                task_type: string_field(row, "task_type", PER_TASK_RESULTS_JSON)?,
                runner: string_field(row, "runner", PER_TASK_RESULTS_JSON)?,
                diagnostic_label: string_field(row, "diagnostic_label", PER_TASK_RESULTS_JSON)?,
                prompt_tokens: u64_field(row, "prompt_tokens", PER_TASK_RESULTS_JSON)?,
                total_cost_micro_exo: u64_field(
                    row,
                    "total_cost_micro_exo",
                    PER_TASK_RESULTS_JSON,
                )?,
                latency_ms: u64_field(row, "latency_ms", PER_TASK_RESULTS_JSON)?,
                quality_score_bp: u64_field(row, "quality_score_bp", PER_TASK_RESULTS_JSON)?,
                citation_accuracy_bp: u64_field(
                    row,
                    "citation_accuracy_bp",
                    PER_TASK_RESULTS_JSON,
                )?,
                unsupported_claim_rate_bp: u64_field(
                    row,
                    "unsupported_claim_rate_bp",
                    PER_TASK_RESULTS_JSON,
                )?,
                selected_refs: u64_field(row, "selected_refs", PER_TASK_RESULTS_JSON)?,
                route_count: u64_field(row, "route_count", PER_TASK_RESULTS_JSON)?,
                context_packet_tokens: u64_field(
                    row,
                    "context_packet_tokens",
                    PER_TASK_RESULTS_JSON,
                )?,
                overall_diagnostic_claim_allowed: bool_field(
                    row,
                    "overall_diagnostic_claim_allowed",
                    PER_TASK_RESULTS_JSON,
                )?,
                reason_if_disallowed: optional_string_field(
                    row,
                    "reason_if_disallowed",
                    PER_TASK_RESULTS_JSON,
                )?,
            })
        })
        .collect()
}

fn build_traceability(
    rows: &[DiagnosticBrowserPerTaskResult],
) -> Vec<DiagnosticBrowserTraceability> {
    rows.iter()
        .map(|row| DiagnosticBrowserTraceability {
            fixture_kind: row.fixture_kind.clone(),
            task_id: row.task_id.clone(),
            runner: row.runner.clone(),
            selected_refs: row.selected_refs,
            route_count: row.route_count,
            context_packet_tokens: row.context_packet_tokens,
            reason_if_disallowed: row.reason_if_disallowed.clone(),
        })
        .collect()
}

fn series_from_rows(
    metric: &str,
    rows: &[DiagnosticBrowserPerTaskResult],
) -> DiagnosticBrowserSeries {
    let points = rows
        .iter()
        .map(|row| DiagnosticBrowserSeriesPoint {
            fixture_kind: row.fixture_kind.clone(),
            task_id: row.task_id.clone(),
            runner: row.diagnostic_label.clone(),
            value: match metric {
                "latency_ms" => row.latency_ms,
                "total_cost_micro_exo" => row.total_cost_micro_exo,
                "quality_score_bp" => row.quality_score_bp,
                "citation_accuracy_bp" => row.citation_accuracy_bp,
                "unsupported_claim_rate_bp" => row.unsupported_claim_rate_bp,
                "selected_refs" => row.selected_refs,
                "context_packet_tokens" => row.context_packet_tokens,
                _ => row.prompt_tokens,
            },
        })
        .collect();
    DiagnosticBrowserSeries {
        metric: metric.into(),
        points,
    }
}

fn unavailable_graph_views() -> Vec<DiagnosticBrowserGraphView> {
    [
        DatabaseRole::Main,
        DatabaseRole::ControlBenchmark,
        DatabaseRole::GovernedBenchmark,
    ]
    .iter()
    .copied()
    .map(|role| DiagnosticBrowserGraphView {
        silo_role: role,
        graph_style: "not_available".into(),
        source: "none".into(),
        availability_status: "not_available".into(),
        partial: false,
        nodes: Vec::new(),
        edges: Vec::new(),
        message: GRAPH_UNAVAILABLE_MESSAGE.into(),
    })
    .collect()
}

fn recommendations_from(summary: &Value, markdown: Option<String>) -> Vec<String> {
    let mut recommendations = path_value(summary, "recommendations", SUMMARY_JSON)
        .ok()
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(text) = markdown
        && recommendations.is_empty()
    {
        recommendations.push(text);
    }
    recommendations
}

fn generated_from_paths() -> Vec<String> {
    [
        SUMMARY_JSON,
        SUMMARY_MD,
        PER_TASK_RESULTS_JSON,
        LATENCY_BREAKDOWN_JSON,
        COST_BREAKDOWN_JSON,
        QUALITY_BREAKDOWN_JSON,
        RECOMMENDATIONS_MD,
    ]
    .iter()
    .map(|artifact| format!("target/dagdb/end_to_end_diagnostics/{artifact}"))
    .collect()
}

fn string_field(value: &Value, key: &str, artifact: &str) -> Result<String, BrowserError> {
    path_value(value, key, artifact)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed(artifact))
}

fn optional_string_field(
    value: &Value,
    key: &str,
    artifact: &str,
) -> Result<Option<String>, BrowserError> {
    let field = path_value(value, key, artifact)?;
    if field.is_null() {
        Ok(None)
    } else {
        field
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| malformed(artifact))
    }
}

fn string_vec_field(value: &Value, key: &str, artifact: &str) -> Result<Vec<String>, BrowserError> {
    require_array(path_value(value, key, artifact)?, artifact)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| malformed(artifact))
        })
        .collect()
}

fn bool_field(value: &Value, key: &str, artifact: &str) -> Result<bool, BrowserError> {
    path_value(value, key, artifact)?
        .as_bool()
        .ok_or_else(|| malformed(artifact))
}

fn u64_field(value: &Value, key: &str, artifact: &str) -> Result<u64, BrowserError> {
    path_value(value, key, artifact)?
        .as_u64()
        .ok_or_else(|| malformed(artifact))
}

fn optional_u64_field(
    value: &Value,
    key: &str,
    artifact: &str,
) -> Result<Option<u64>, BrowserError> {
    let field = path_value(value, key, artifact)?;
    if field.is_null() {
        Ok(None)
    } else {
        field.as_u64().map(Some).ok_or_else(|| malformed(artifact))
    }
}

fn i64_field(value: &Value, key: &str, artifact: &str) -> Result<i64, BrowserError> {
    path_value(value, key, artifact)?
        .as_i64()
        .ok_or_else(|| malformed(artifact))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    fn env_lookup_from<'a>(configured: &'a [&'a str]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            configured
                .iter()
                .any(|candidate| candidate == &key)
                .then(|| "postgres://user:password@example.invalid/db?token=secret".into())
        }
    }

    fn status_with_all_envs() -> Vec<DatabaseSiloStatus> {
        database_silo_statuses_from_env(env_lookup_from(&[
            "EXO_DAGDB_MAIN_DATABASE_URL",
            "EXO_DAGDB_CONTROL_BENCH_DATABASE_URL",
            "EXO_DAGDB_GOVERNED_BENCH_DATABASE_URL",
        ]))
    }

    fn fixture_dir(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join("exo_dagdb_browser_tests")
            .join(name)
    }

    fn write_minimal_reports(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
        fs::create_dir_all(dir).expect("test report dir");
        fs::write(
            dir.join(SUMMARY_JSON),
            json!({
                "deterministic_mode": true,
                "live_model_status": "SKIP live external model benchmark: operator approval not provided.",
                "replay_fixture_status": "SKIP project/session replay fixture: redaction-safe replay fixture not implemented.",
                "optimized_runner_status": "governed_dagdb_optimized included",
                "fixture_ids": ["dagdb_mvp_minimum_v1"],
                "runner_aggregates": [{
                    "fixture_kind": "mvp_synthetic",
                    "fixture_id": "dagdb_mvp_minimum_v1",
                    "runner": "long_context_dump",
                    "diagnostic_label": "neutral_long_context",
                    "task_count": 1,
                    "total_prompt_tokens": 100,
                    "total_cost_micro_exo": 500,
                    "average_latency_ms": 10,
                    "average_quality_score_bp": 9000,
                    "average_citation_accuracy_bp": 9800,
                    "average_unsupported_claim_rate_bp": 100
                }],
                "comparisons": [{
                    "comparison_name": "primary_ab_long_context_vs_governed_dagdb",
                    "fixture_kind": "mvp_synthetic",
                    "neutral_runner": "neutral_long_context",
                    "dag_runner": "governed_dagdb",
                    "fairness_passed": true,
                    "cost_savings_claim_allowed": true,
                    "quality_improvement_claim_allowed": true,
                    "overall_diagnostic_claim_allowed": true,
                    "token_reduction_bp": 5000,
                    "cost_reduction_bp": 3000,
                    "quality_delta_bp": 100,
                    "citation_delta_bp": 50,
                    "unsupported_claim_improvement_bp": 10,
                    "latency_delta_ms": 2,
                    "net_savings_micro_exo": 100
                }],
                "recommendations": ["Add replay data."]
            })
            .to_string(),
        )
        .expect("summary");
        fs::write(
            dir.join(PER_TASK_RESULTS_JSON),
            json!([{
                "fixture_kind": "mvp_synthetic",
                "fixture_id": "dagdb_mvp_minimum_v1",
                "task_id": "t001",
                "task_type": "architecture_recall",
                "runner": "long_context_dump",
                "diagnostic_label": "neutral_long_context",
                "prompt_tokens": 100,
                "total_cost_micro_exo": 500,
                "latency_ms": 10,
                "quality_score_bp": 9000,
                "citation_accuracy_bp": 9800,
                "unsupported_claim_rate_bp": 100,
                "selected_refs": 8,
                "route_count": 2,
                "context_packet_tokens": 64,
                "overall_diagnostic_claim_allowed": true,
                "reason_if_disallowed": null
            }])
            .to_string(),
        )
        .expect("per task");
        for artifact in [
            LATENCY_BREAKDOWN_JSON,
            COST_BREAKDOWN_JSON,
            QUALITY_BREAKDOWN_JSON,
        ] {
            fs::write(dir.join(artifact), "{}").expect("supporting json");
        }
        fs::write(dir.join(RECOMMENDATIONS_MD), "# Recommendations\n").expect("recommendations");
    }

    fn read_report_json(dir: &Path, artifact: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(dir.join(artifact)).expect("read report"))
            .expect("json report")
    }

    fn write_report_json(dir: &Path, artifact: &str, value: Value) {
        fs::write(dir.join(artifact), value.to_string()).expect("write report")
    }

    #[test]
    fn browser_database_role_config_separates_main_control_governed() {
        let configs = benchmark_database_configs();
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].role, DatabaseRole::Main);
        assert_eq!(configs[1].role, DatabaseRole::ControlBenchmark);
        assert_eq!(configs[2].role, DatabaseRole::GovernedBenchmark);
        assert_ne!(configs[1].database_url_env, configs[2].database_url_env);
    }

    #[test]
    fn browser_main_db_disallows_synthetic_benchmark_writes_by_default() {
        let main = benchmark_database_configs()
            .into_iter()
            .find(|config| config.role == DatabaseRole::Main)
            .expect("main config");
        assert!(main.read_only);
        assert!(!main.allow_benchmark_writes);
        assert!(!main.allow_synthetic_data);
        assert!(!main.real_private_data_access_allowed);
    }

    #[test]
    fn browser_control_profile_disables_dag_graph_routing() {
        let control = benchmark_database_configs()
            .into_iter()
            .find(|config| config.role == DatabaseRole::ControlBenchmark)
            .expect("control config");
        assert!(!control.graph_routing_enabled);
    }

    #[test]
    fn browser_governed_profile_enables_dag_graph_routing() {
        let governed = benchmark_database_configs()
            .into_iter()
            .find(|config| config.role == DatabaseRole::GovernedBenchmark)
            .expect("governed config");
        assert!(governed.graph_routing_enabled);
    }

    #[test]
    fn browser_database_silos_json_omits_database_urls_and_secrets() {
        let statuses = status_with_all_envs();
        let json = serde_json::to_string(&statuses).expect("json");
        for forbidden in [
            "postgres://",
            "password",
            "token",
            "secret",
            "database_url",
            "connection_string",
            "example.invalid",
        ] {
            assert!(!json.contains(forbidden), "leaked {forbidden}");
        }
        assert!(json.contains("EXO_DAGDB_MAIN_DATABASE_URL"));
        assert!(
            statuses
                .iter()
                .all(|status| !status.real_private_data_access_allowed)
        );
    }

    #[test]
    fn browser_database_silo_statuses_cover_unconfigured_and_risk_branches() {
        let statuses = database_silo_statuses_from_env(env_lookup_from(&[]));
        assert!(
            statuses
                .iter()
                .all(|status| status.isolation_status == "not_fully_configured")
        );
        assert!(
            statuses
                .iter()
                .all(|status| status.contamination_risk_status == "not_configured")
        );

        let main_risk = contamination_risk_status(
            &BenchmarkDatabaseConfig {
                role: DatabaseRole::Main,
                database_url_env: "EXO_DAGDB_MAIN_DATABASE_URL".into(),
                tenant_id: "main".into(),
                namespace: "production".into(),
                read_only: true,
                allow_benchmark_writes: true,
                allow_synthetic_data: false,
                real_private_data_access_allowed: false,
                graph_routing_enabled: true,
            },
            true,
        );
        assert_eq!(main_risk, "blocked_main_contamination_risk");

        let control_risk = contamination_risk_status(
            &BenchmarkDatabaseConfig {
                role: DatabaseRole::ControlBenchmark,
                database_url_env: "EXO_DAGDB_CONTROL_BENCH_DATABASE_URL".into(),
                tenant_id: "benchmark_control".into(),
                namespace: "control_benchmark".into(),
                read_only: true,
                allow_benchmark_writes: false,
                allow_synthetic_data: true,
                real_private_data_access_allowed: false,
                graph_routing_enabled: true,
            },
            true,
        );
        assert_eq!(control_risk, "blocked_control_graph_routing_risk");
    }

    #[test]
    fn browser_missing_diagnostic_reports_emit_missing_state() {
        let dir = fixture_dir("missing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let error = build_diagnostic_browser_view_model(&dir, status_with_all_envs())
            .expect_err("missing reports");
        assert!(matches!(
            error,
            BrowserError::MissingReports {
                message: MISSING_REPORT_MESSAGE,
                ..
            }
        ));
    }

    #[test]
    fn browser_report_ingestion_parses_required_artifacts() {
        let dir = fixture_dir("valid");
        write_minimal_reports(&dir);
        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert_eq!(model.schema_version, DIAGNOSTIC_BROWSER_SCHEMA_VERSION);
        assert_eq!(model.runner_rollups.len(), 1);
        assert_eq!(model.comparisons.len(), 1);
        assert_eq!(model.per_task_results.len(), 1);
    }

    #[test]
    fn browser_report_ingestion_covers_optional_null_and_warning_paths() {
        let dir = fixture_dir("optional_paths");
        write_minimal_reports(&dir);

        let mut summary = read_report_json(&dir, SUMMARY_JSON);
        summary["comparisons"][0]["token_reduction_bp"] = Value::Null;
        summary["recommendations"] = json!([]);
        write_report_json(&dir, SUMMARY_JSON, summary);

        let mut per_task = read_report_json(&dir, PER_TASK_RESULTS_JSON);
        per_task[0]["reason_if_disallowed"] = json!("per_task_claim_non_authoritative");
        write_report_json(&dir, PER_TASK_RESULTS_JSON, per_task);
        fs::write(dir.join(SUMMARY_MD), "# Summary\n").expect("summary md");

        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert!(model.comparisons[0].token_reduction_bp.is_none());
        assert_eq!(
            model.per_task_results[0].reason_if_disallowed.as_deref(),
            Some("per_task_claim_non_authoritative")
        );
        assert_eq!(model.recommendations, vec!["# Recommendations\n"]);
        assert!(model.warnings.is_empty());

        fs::remove_file(dir.join(RECOMMENDATIONS_MD)).expect("remove recommendations");
        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert_eq!(
            model.warnings,
            vec!["recommendations.md unavailable or malformed"]
        );
    }

    #[test]
    fn browser_report_ingestion_reports_malformed_json_and_shape() {
        let dir = fixture_dir("malformed");
        write_minimal_reports(&dir);
        fs::write(dir.join(SUMMARY_JSON), "{not-json").expect("bad json");
        let error = build_diagnostic_browser_view_model(&dir, status_with_all_envs())
            .expect_err("json error");
        assert_eq!(
            error.to_string(),
            "browser_report_json_failed: summary.json"
        );

        write_minimal_reports(&dir);
        fs::write(dir.join(SUMMARY_JSON), "[]").expect("bad shape");
        let error = build_diagnostic_browser_view_model(&dir, status_with_all_envs())
            .expect_err("malformed error");
        assert_eq!(
            error.to_string(),
            format!("{MALFORMED_REPORT_MESSAGE}: {SUMMARY_JSON}")
        );
    }

    #[test]
    fn browser_view_model_computes_runner_rollups_deterministically() {
        let dir = fixture_dir("deterministic");
        write_minimal_reports(&dir);
        let first =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("first");
        let second =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("second");
        assert_eq!(first, second);
        assert_eq!(first.runner_rollups[0].total_prompt_tokens, 100);
        assert_eq!(first.quality_series.len(), 6);
    }

    #[test]
    fn browser_view_model_schema_version_is_locked() {
        let dir = fixture_dir("schema");
        write_minimal_reports(&dir);
        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert_eq!(model.schema_version, "dagdb_diagnostic_browser_v1");
    }

    #[test]
    fn browser_graph_view_returns_not_available_when_absent() {
        let dir = fixture_dir("graph_absent");
        write_minimal_reports(&dir);
        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert_eq!(model.graph_views.len(), 3);
        assert!(
            model
                .graph_views
                .iter()
                .all(|view| view.message == GRAPH_UNAVAILABLE_MESSAGE)
        );
    }

    #[test]
    fn browser_graph_view_does_not_fabricate_nodes() {
        let dir = fixture_dir("graph_empty");
        write_minimal_reports(&dir);
        let model =
            build_diagnostic_browser_view_model(&dir, status_with_all_envs()).expect("view model");
        assert!(model.graph_views.iter().all(|view| view.nodes.is_empty()));
        assert!(model.graph_views.iter().all(|view| view.edges.is_empty()));
    }
}
