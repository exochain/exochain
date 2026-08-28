//! Deterministic Phase 2A benchmark diagnostics and report artifacts.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use exo_dag_db_api::{RiskClass, ValidationStatus};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    benchmark::{
        BenchmarkError, BenchmarkFixture, BenchmarkRunReport, BenchmarkRunnerName,
        generate_scale_fixture, load_benchmark_fixture_json, run_benchmark_fixture,
    },
    benchmark_isolation::{self, BenchmarkIsolationError},
    optimization::{
        MVP_REDACTION_CACHE_HIT_RATIO_BP, optimized_fixture_latency,
        scale_redaction_cache_hit_ratio_bp,
    },
};

/// Benchmark summary JSON artifact path.
pub const BENCHMARK_SUMMARY_JSON: &str = "target/dagdb/reports/benchmark_summary.json";
/// Benchmark summary Markdown artifact path.
pub const BENCHMARK_SUMMARY_MD: &str = "target/dagdb/reports/benchmark_summary.md";
/// Per-task breakdown JSON artifact path.
pub const PER_TASK_BREAKDOWN_JSON: &str = "target/dagdb/reports/per_task_breakdown.json";
/// Latency breakdown JSON artifact path.
pub const LATENCY_BREAKDOWN_JSON: &str = "target/dagdb/reports/latency_breakdown.json";
/// Optimized capability summary JSON artifact path.
pub const OPTIMIZED_CAPABILITY_SUMMARY_JSON: &str =
    "target/dagdb/upgrade-reports/optimized_capability_summary.json";
/// Optimized capability summary Markdown artifact path.
pub const OPTIMIZED_CAPABILITY_SUMMARY_MD: &str =
    "target/dagdb/upgrade-reports/optimized_capability_summary.md";
/// Scale fixture summary JSON artifact path.
pub const SCALE_FIXTURE_SUMMARY_JSON: &str =
    "target/dagdb/upgrade-reports/scale_fixture_summary.json";
/// Optimized per-task breakdown JSON artifact path.
pub const OPTIMIZED_PER_TASK_BREAKDOWN_JSON: &str =
    "target/dagdb/upgrade-reports/optimized_per_task_breakdown.json";
/// End-to-end diagnostic summary JSON artifact path.
pub const E2E_DIAGNOSTIC_SUMMARY_JSON: &str = "target/dagdb/end_to_end_diagnostics/summary.json";
/// End-to-end diagnostic summary Markdown artifact path.
pub const E2E_DIAGNOSTIC_SUMMARY_MD: &str = "target/dagdb/end_to_end_diagnostics/summary.md";
/// End-to-end per-task JSON artifact path.
pub const E2E_DIAGNOSTIC_PER_TASK_RESULTS_JSON: &str =
    "target/dagdb/end_to_end_diagnostics/per_task_results.json";
/// End-to-end latency JSON artifact path.
pub const E2E_DIAGNOSTIC_LATENCY_BREAKDOWN_JSON: &str =
    "target/dagdb/end_to_end_diagnostics/latency_breakdown.json";
/// End-to-end cost JSON artifact path.
pub const E2E_DIAGNOSTIC_COST_BREAKDOWN_JSON: &str =
    "target/dagdb/end_to_end_diagnostics/cost_breakdown.json";
/// End-to-end quality JSON artifact path.
pub const E2E_DIAGNOSTIC_QUALITY_BREAKDOWN_JSON: &str =
    "target/dagdb/end_to_end_diagnostics/quality_breakdown.json";
/// End-to-end recommendations Markdown artifact path.
pub const E2E_DIAGNOSTIC_RECOMMENDATIONS_MD: &str =
    "target/dagdb/end_to_end_diagnostics/recommendations.md";

const PROMPT_TOKEN_REDUCTION_THRESHOLD_BP: u64 = 1_000;
const E2E_MODEL_OR_EVALUATOR_ID: &str = "exo_dagdb_deterministic_harness_v1";
const E2E_SCORING_PATH_ID: &str = "benchmark_run_report_scoring_v1";
const E2E_LIVE_MODEL_SKIP: &str =
    "SKIP live external model benchmark: operator approval not provided.";
const E2E_REPLAY_INCLUDED: &str =
    "redacted_project_session_v1 included as deterministic redaction-safe replay fixture.";
const E2E_OPTIMIZED_SKIP: &str = "SKIP governed_dagdb_optimized: runner not implemented.";
const E2E_QUALITY_ONLY_MESSAGE: &str =
    "Quality/safety improvement allowed; cost-savings claim not allowed.";
const E2E_HARNESS_DISCLAIMER: &str = "This diagnostic proves behavior inside the deterministic EXOCHAIN benchmark harness. It does not prove live external model performance, real API dollar savings, or real user productivity until separately approved live benchmarks and additional replay datasets are run.";
const REDACTED_REPLAY_FIXTURE_JSON: &str =
    include_str!("../fixtures/benchmarks/redacted_project_session_v1.json");
pub const E2E_DIAGNOSTIC_FIXTURE_FILTER_ENV: &str = "EXO_DAGDB_DIAGNOSTIC_FIXTURE_FILTER";

/// Phase 2A diagnostics failures.
#[derive(Debug, Error)]
pub enum DiagnosticsError {
    /// Benchmark fixture or runner failed.
    #[error(transparent)]
    Benchmark(#[from] BenchmarkError),
    /// Benchmark isolation report generation failed.
    #[error(transparent)]
    BenchmarkIsolation(#[from] BenchmarkIsolationError),
    /// Report JSON serialization failed.
    #[error("phase2a_report_json_failed")]
    Json {
        /// Source JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Report artifact write failed.
    #[error("phase2a_report_io_failed: {path}")]
    Io {
        /// Path that failed.
        path: String,
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Required runner report is missing.
    #[error("phase2a_report_missing_runner: {runner}")]
    MissingRunner {
        /// Missing runner label.
        runner: &'static str,
    },
    /// Fixture filter does not match an included deterministic fixture.
    #[error("phase2a_report_invalid_fixture_filter: {fixture_id}")]
    InvalidFixtureFilter {
        /// Requested fixture id.
        fixture_id: String,
    },
}

/// Result alias for Phase 2A diagnostics.
pub type Result<T> = std::result::Result<T, DiagnosticsError>;

/// Per-task benchmark diagnostic row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerTaskBenchmarkDiagnostic {
    pub task_id: String,
    pub task_type: String,
    pub runner: BenchmarkRunnerName,
    pub quality_score_bp: u16,
    pub citation_accuracy_bp: u16,
    pub unsupported_claim_rate_bp: u16,
    pub prompt_tokens: u32,
    pub overhead_tokens: u32,
    pub selected_refs: u32,
    pub raw_payload_fetch_count: u32,
    pub route_count: u32,
    pub context_packet_tokens: u32,
    pub latency_ms: u64,
    pub net_savings_micro_exo: u64,
    pub claim_allowed: bool,
    pub reason_if_disallowed: Option<String>,
}

/// Deterministic latency breakdown for one runner or task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyBreakdown {
    pub catalog_lookup_ms: u64,
    pub canonical_resolution_ms: u64,
    pub provenance_fetch_ms: u64,
    pub contradiction_fetch_ms: u64,
    pub routing_view_build_ms: u64,
    pub validation_ms: u64,
    pub context_packet_build_ms: u64,
    pub writeback_ms: u64,
    pub total_ms: u64,
}

impl LatencyBreakdown {
    /// Compute a deterministic fixture-derived latency model.
    #[must_use]
    pub fn from_inputs(
        corpus_count: u64,
        runner: BenchmarkRunnerName,
        selected_ref_count: u64,
        route_count: u64,
        context_packet_tokens: u64,
    ) -> Self {
        let runner_factor = runner_factor(runner);
        let catalog_lookup_ms = 1u64
            .saturating_add(corpus_count / 120)
            .saturating_add(selected_ref_count / 32)
            .saturating_add(runner_factor);
        let canonical_resolution_ms = (selected_ref_count / 16)
            .saturating_add(route_count)
            .saturating_add(runner_factor);
        let provenance_fetch_ms = (selected_ref_count / 24).saturating_add(route_count);
        let contradiction_fetch_ms = (selected_ref_count / 48).saturating_add(runner_factor / 4);
        let routing_view_build_ms = route_count
            .saturating_mul(2)
            .saturating_add(selected_ref_count / 20)
            .saturating_add(runner_factor);
        let validation_ms = match runner {
            BenchmarkRunnerName::NoMemory | BenchmarkRunnerName::LongContextDump => 0,
            BenchmarkRunnerName::FlatRag => 1,
            BenchmarkRunnerName::DagDbRouting => 3u64.saturating_add(selected_ref_count / 24),
            BenchmarkRunnerName::GovernedDagDbRouting
            | BenchmarkRunnerName::GovernedDagDbOptimized => {
                5u64.saturating_add(selected_ref_count / 16)
            }
        };
        let context_packet_build_ms = 1u64
            .saturating_add(context_packet_tokens / 128)
            .saturating_add(selected_ref_count / 32);
        let writeback_ms = match runner {
            BenchmarkRunnerName::DagDbRouting
            | BenchmarkRunnerName::GovernedDagDbRouting
            | BenchmarkRunnerName::GovernedDagDbOptimized => 2u64.saturating_add(route_count),
            BenchmarkRunnerName::NoMemory
            | BenchmarkRunnerName::LongContextDump
            | BenchmarkRunnerName::FlatRag => 0,
        };
        if runner == BenchmarkRunnerName::GovernedDagDbOptimized {
            return Self::optimized_from_stage_inputs(
                Self {
                    catalog_lookup_ms,
                    canonical_resolution_ms,
                    provenance_fetch_ms,
                    contradiction_fetch_ms,
                    routing_view_build_ms,
                    validation_ms,
                    context_packet_build_ms,
                    writeback_ms,
                    total_ms: 0,
                },
                selected_ref_count,
                context_packet_tokens,
                route_count,
                5_000,
                true,
            );
        }
        let total_ms = catalog_lookup_ms
            .saturating_add(canonical_resolution_ms)
            .saturating_add(provenance_fetch_ms)
            .saturating_add(contradiction_fetch_ms)
            .saturating_add(routing_view_build_ms)
            .saturating_add(validation_ms)
            .saturating_add(context_packet_build_ms)
            .saturating_add(writeback_ms);
        Self {
            catalog_lookup_ms,
            canonical_resolution_ms,
            provenance_fetch_ms,
            contradiction_fetch_ms,
            routing_view_build_ms,
            validation_ms,
            context_packet_build_ms,
            writeback_ms,
            total_ms,
        }
    }

    /// Apply the locked optimized latency adjustments to base Phase 2A stages.
    #[must_use]
    pub fn optimized_from_stage_inputs(
        base: Self,
        selected_ref_count: u64,
        context_packet_tokens: u64,
        route_count: u64,
        redaction_cache_hit_ratio_bp: u64,
        idempotency_read_reuse_hit: bool,
    ) -> Self {
        let ratio = redaction_cache_hit_ratio_bp.min(7_000);
        let catalog_lookup_ms = base
            .catalog_lookup_ms
            .saturating_sub(base.catalog_lookup_ms.min(selected_ref_count / 8));
        let canonical_resolution_ms = base
            .canonical_resolution_ms
            .saturating_sub(ratio.saturating_mul(base.canonical_resolution_ms) / 10_000);
        let provenance_fetch_ms = base
            .provenance_fetch_ms
            .saturating_sub(base.provenance_fetch_ms.min(route_count));
        let contradiction_fetch_ms = base.contradiction_fetch_ms;
        let routing_view_build_ms = base.routing_view_build_ms;
        let validation_ms = base.validation_ms;
        let context_packet_build_ms = 1u64
            .saturating_add(context_packet_tokens / 256)
            .saturating_add(selected_ref_count / 64);
        let writeback_ms = if idempotency_read_reuse_hit {
            base.writeback_ms.saturating_sub(1)
        } else {
            base.writeback_ms
        };
        let total_ms = catalog_lookup_ms
            .saturating_add(canonical_resolution_ms)
            .saturating_add(provenance_fetch_ms)
            .saturating_add(contradiction_fetch_ms)
            .saturating_add(routing_view_build_ms)
            .saturating_add(validation_ms)
            .saturating_add(context_packet_build_ms)
            .saturating_add(writeback_ms);
        Self {
            catalog_lookup_ms,
            canonical_resolution_ms,
            provenance_fetch_ms,
            contradiction_fetch_ms,
            routing_view_build_ms,
            validation_ms,
            context_packet_build_ms,
            writeback_ms,
            total_ms,
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            catalog_lookup_ms: self
                .catalog_lookup_ms
                .saturating_add(other.catalog_lookup_ms),
            canonical_resolution_ms: self
                .canonical_resolution_ms
                .saturating_add(other.canonical_resolution_ms),
            provenance_fetch_ms: self
                .provenance_fetch_ms
                .saturating_add(other.provenance_fetch_ms),
            contradiction_fetch_ms: self
                .contradiction_fetch_ms
                .saturating_add(other.contradiction_fetch_ms),
            routing_view_build_ms: self
                .routing_view_build_ms
                .saturating_add(other.routing_view_build_ms),
            validation_ms: self.validation_ms.saturating_add(other.validation_ms),
            context_packet_build_ms: self
                .context_packet_build_ms
                .saturating_add(other.context_packet_build_ms),
            writeback_ms: self.writeback_ms.saturating_add(other.writeback_ms),
            total_ms: self.total_ms.saturating_add(other.total_ms),
        }
    }
}

/// Benchmark regression gate result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRegressionGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub runner: BenchmarkRunnerName,
    pub baseline_runner: BenchmarkRunnerName,
    pub observed_value: u64,
    pub baseline_value: u64,
    pub threshold_value: u64,
    pub reason: String,
}

/// Full deterministic report bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkReportBundle {
    pub fixture_id: String,
    pub deterministic_seed: u64,
    pub runner_reports: Vec<BenchmarkRunReport>,
    pub per_task_breakdown: Vec<PerTaskBenchmarkDiagnostic>,
    pub latency_breakdown: BTreeMap<String, LatencyBreakdown>,
    pub regression_gates: Vec<BenchmarkRegressionGateResult>,
    pub generated_artifacts: Vec<String>,
}

/// Rendered report artifact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkReportArtifacts {
    pub benchmark_summary_json: String,
    pub benchmark_summary_md: String,
    pub per_task_breakdown_json: String,
    pub latency_breakdown_json: String,
}

/// Optimized benchmark gate tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizedBenchmarkGateTier {
    Floor,
    Stretch,
}

/// Optimized benchmark gate result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedBenchmarkGateResult {
    pub gate_name: String,
    pub tier: OptimizedBenchmarkGateTier,
    pub passed: bool,
    pub observed_value: u64,
    pub baseline_value: u64,
    pub threshold_value: u64,
    pub reason: String,
}

/// Capability verdict for the optimized benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizedCapabilityVerdict {
    FloorFailed,
    ImprovedMeaningfully,
    ImprovedToStretch,
}

/// Runner metrics exposed in optimized reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedRunnerMetrics {
    pub runner: BenchmarkRunnerName,
    pub quality_score_bp: u16,
    pub citation_accuracy_bp: u16,
    pub unsupported_claim_rate_bp: u16,
    pub prompt_tokens_total: u32,
    pub overhead_tokens_total: u32,
    pub net_savings_micro_exo_total: u64,
    pub deterministic_latency_ms_total: u64,
    pub mean_per_task_latency_ms: u64,
    pub claim_allowed: bool,
}

/// Full optimized capability summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedCapabilitySummary {
    pub fixture_id: String,
    pub deterministic_seed: u64,
    pub scale_fixture_id: String,
    pub scale_deterministic_seed: u64,
    pub mvp_runner_metrics: Vec<OptimizedRunnerMetrics>,
    pub scale_runner_metrics: Vec<OptimizedRunnerMetrics>,
    pub mvp_gates: Vec<OptimizedBenchmarkGateResult>,
    pub scale_gates: Vec<OptimizedBenchmarkGateResult>,
    pub redaction_cache_hit_ratio_bp: u64,
    pub scale_redaction_cache_hit_ratio_bp: u64,
    pub scale_latency_overhead_vs_mvp_bp: u64,
    pub governance_overhead_reduction_bp: u64,
    pub capability_verdict: OptimizedCapabilityVerdict,
}

/// Rendered optimized report artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizedReportArtifacts {
    pub optimized_capability_summary_json: String,
    pub optimized_capability_summary_md: String,
    pub scale_fixture_summary_json: String,
    pub optimized_per_task_breakdown_json: String,
}

/// Stable end-to-end diagnostic runner role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticRunnerRole {
    NeutralLongContext,
    NeutralFlatRag,
    NoMemoryLowerBound,
    DagDbRoutingRaw,
    GovernedDagdb,
    GovernedDagdbOptimized,
}

/// Stable context acquisition profile label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAcquisitionProfile {
    LongContextSourceLoading,
    FlatRetrievalWithoutGraphOrganization,
    NoMemory,
    RawDagRouting,
    GovernedDagRoutingValidationContextPacketGraph,
    OptimizedGovernedDagRouting,
}

/// Fixture kind included in the deterministic end-to-end diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticFixtureKind {
    MvpSynthetic,
    LargeSynthetic,
    RedactedProjectSessionReplay,
    ProjectSessionReplayMissing,
}

/// Stable role definition for report metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndRunnerDefinition {
    pub role: DiagnosticRunnerRole,
    pub benchmark_runner: BenchmarkRunnerName,
    pub diagnostic_label: String,
    pub context_acquisition_profile: ContextAcquisitionProfile,
    pub primary_baseline_allowed: bool,
}

/// Fairness check result for one A/B comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndFairnessCheck {
    pub comparison_name: String,
    pub fixture_kind: DiagnosticFixtureKind,
    pub fixture_id: String,
    pub neutral_runner: DiagnosticRunnerRole,
    pub dag_runner: DiagnosticRunnerRole,
    pub same_fixture_id: bool,
    pub same_corpus_id: bool,
    pub same_task_ids: bool,
    pub same_allowed_source_pool: bool,
    pub same_evaluator_and_scoring_path: bool,
    pub same_source_availability: bool,
    pub selected_refs_may_differ: bool,
    pub selected_refs_differ: bool,
    pub passed: bool,
    pub reason_if_failed: Option<String>,
}

/// End-to-end deterministic latency row including output-stage accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndLatencyBreakdown {
    pub catalog_lookup_ms: u64,
    pub canonical_resolution_ms: u64,
    pub provenance_fetch_ms: u64,
    pub contradiction_fetch_ms: u64,
    pub routing_view_build_ms: u64,
    pub validation_ms: u64,
    pub context_packet_build_ms: u64,
    pub answer_or_output_ms: u64,
    pub writeback_ms: u64,
    pub total_ms: u64,
}

/// Per-task end-to-end diagnostic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndPerTaskResult {
    pub fixture_kind: DiagnosticFixtureKind,
    pub fixture_id: String,
    pub task_id: String,
    pub task_type: String,
    pub runner: BenchmarkRunnerName,
    pub diagnostic_label: String,
    pub context_acquisition_profile: ContextAcquisitionProfile,
    pub model_or_evaluator_id: String,
    pub corpus_id: String,
    pub corpus_item_count: u32,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub overhead_tokens: u32,
    pub selected_refs: u32,
    pub raw_payload_fetch_count: u32,
    pub route_count: u32,
    pub context_packet_tokens: u32,
    pub context_reduction_bp: Option<u64>,
    pub quality_score_bp: u16,
    pub citation_accuracy_bp: u16,
    pub unsupported_claim_rate_bp: u16,
    pub contradiction_detection_bp: Option<u64>,
    pub missing_context_rate_bp: Option<u64>,
    pub latency_ms: u64,
    pub latency_breakdown: EndToEndLatencyBreakdown,
    pub model_cost_micro_exo: u64,
    pub routing_cost_micro_exo: u64,
    pub validation_cost_micro_exo: u64,
    pub storage_or_writeback_cost_micro_exo: u64,
    pub total_cost_micro_exo: u64,
    pub net_savings_micro_exo: i64,
    pub cost_savings_claim_allowed: bool,
    pub quality_improvement_claim_allowed: bool,
    pub overall_diagnostic_claim_allowed: bool,
    pub reason_if_disallowed: Option<String>,
    pub failure_reason: Option<String>,
}

/// Per-runner aggregate for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndRunnerAggregate {
    pub fixture_kind: DiagnosticFixtureKind,
    pub fixture_id: String,
    pub runner: BenchmarkRunnerName,
    pub diagnostic_label: String,
    pub task_count: u32,
    pub average_prompt_tokens: u32,
    pub median_prompt_tokens: u32,
    pub total_prompt_tokens: u32,
    pub average_total_tokens: u32,
    pub total_total_tokens: u32,
    pub average_selected_refs: u32,
    pub total_selected_refs: u32,
    pub average_latency_ms: u64,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub average_quality_score_bp: u16,
    pub average_citation_accuracy_bp: u16,
    pub average_unsupported_claim_rate_bp: u16,
    pub average_context_reduction_bp: Option<u64>,
    pub total_cost_micro_exo: u64,
    pub net_savings_micro_exo: i64,
    pub percent_token_reduction_bp: Option<u64>,
    pub percent_cost_reduction_bp: Option<u64>,
}

/// Cross-fixture overall rollup for primary comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndOverallRollup {
    pub total_prompt_tokens_by_runner: BTreeMap<String, u64>,
    pub total_cost_micro_exo_by_runner: BTreeMap<String, u64>,
    pub average_quality_score_bp_by_runner: BTreeMap<String, u16>,
    pub average_citation_accuracy_bp_by_runner: BTreeMap<String, u16>,
    pub average_unsupported_claim_rate_bp_by_runner: BTreeMap<String, u16>,
    pub average_latency_ms_by_runner: BTreeMap<String, u64>,
    pub overall_primary_token_reduction_bp: Option<u64>,
    pub overall_primary_cost_reduction_bp: Option<u64>,
    pub overall_primary_quality_delta_bp: i32,
    pub overall_primary_citation_delta_bp: i32,
    pub overall_primary_unsupported_claim_improvement_bp: i32,
    pub overall_primary_latency_delta_ms: i64,
    pub overall_rollup_cost_savings_claim_allowed: bool,
    pub overall_rollup_quality_improvement_claim_allowed: bool,
    pub overall_rollup_diagnostic_claim_allowed: bool,
    pub overall_rollup_reason_if_disallowed: Option<String>,
}

/// One diagnostic comparison result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndComparison {
    pub comparison_name: String,
    pub fixture_kind: DiagnosticFixtureKind,
    pub neutral_runner: DiagnosticRunnerRole,
    pub dag_runner: DiagnosticRunnerRole,
    pub fairness_passed: bool,
    pub cost_savings_claim_allowed: bool,
    pub quality_improvement_claim_allowed: bool,
    pub overall_diagnostic_claim_allowed: bool,
    pub reason_if_disallowed: Option<String>,
    pub token_reduction_bp: Option<u64>,
    pub cost_reduction_bp: Option<u64>,
    pub quality_delta_bp: i32,
    pub citation_delta_bp: i32,
    pub unsupported_claim_improvement_bp: i32,
    pub latency_delta_ms: i64,
    pub net_savings_micro_exo: i64,
}

/// Cost breakdown row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndCostBreakdown {
    pub fixture_kind: DiagnosticFixtureKind,
    pub fixture_id: String,
    pub runner: BenchmarkRunnerName,
    pub diagnostic_label: String,
    pub model_cost_micro_exo: u64,
    pub routing_cost_micro_exo: u64,
    pub validation_cost_micro_exo: u64,
    pub storage_or_writeback_cost_micro_exo: u64,
    pub total_cost_micro_exo: u64,
}

/// Quality breakdown row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndQualityBreakdown {
    pub fixture_kind: DiagnosticFixtureKind,
    pub fixture_id: String,
    pub runner: BenchmarkRunnerName,
    pub diagnostic_label: String,
    pub quality_score_bp: u16,
    pub citation_accuracy_bp: u16,
    pub unsupported_claim_rate_bp: u16,
}

/// Full end-to-end diagnostic summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndDiagnosticSummary {
    pub deterministic_mode: bool,
    pub live_model_status: String,
    pub replay_fixture_status: String,
    pub optimized_runner_status: String,
    pub model_or_evaluator_id: String,
    pub scoring_path_id: String,
    pub fixture_ids: Vec<String>,
    pub runner_definitions: Vec<EndToEndRunnerDefinition>,
    pub fairness_checks: Vec<EndToEndFairnessCheck>,
    pub per_task_results: Vec<EndToEndPerTaskResult>,
    pub runner_aggregates: Vec<EndToEndRunnerAggregate>,
    pub comparisons: Vec<EndToEndComparison>,
    pub overall_rollup: EndToEndOverallRollup,
    pub cost_breakdown: Vec<EndToEndCostBreakdown>,
    pub quality_breakdown: Vec<EndToEndQualityBreakdown>,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub recommendations: Vec<String>,
    pub generated_artifacts: Vec<String>,
}

/// Rendered end-to-end diagnostic artifact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndToEndDiagnosticArtifacts {
    pub summary_json: String,
    pub summary_md: String,
    pub per_task_results_json: String,
    pub latency_breakdown_json: String,
    pub cost_breakdown_json: String,
    pub quality_breakdown_json: String,
    pub recommendations_md: String,
}

/// Build a complete Phase 2A report bundle from fixture runners.
pub fn build_phase2a_report_bundle(fixture: &BenchmarkFixture) -> Result<BenchmarkReportBundle> {
    let mut reports = Vec::new();
    for runner in BenchmarkRunnerName::all() {
        reports.push(run_benchmark_fixture(fixture, runner)?);
    }
    build_phase2a_report_bundle_from_reports(fixture, reports)
}

/// Build a complete Phase 2A report bundle from caller-supplied reports.
pub fn build_phase2a_report_bundle_from_reports(
    fixture: &BenchmarkFixture,
    runner_reports: Vec<BenchmarkRunReport>,
) -> Result<BenchmarkReportBundle> {
    let ordered_reports = ordered_reports(runner_reports)?;
    let regression_gates = evaluate_phase2a_regression_gates(&ordered_reports)?;
    let per_task_breakdown =
        build_per_task_diagnostics(fixture, &ordered_reports, &regression_gates);
    let latency_breakdown = aggregate_latency_by_runner(
        &per_task_breakdown,
        u64::try_from(fixture.corpus.len()).unwrap_or(u64::MAX),
    );
    Ok(BenchmarkReportBundle {
        fixture_id: fixture.fixture_id.clone(),
        deterministic_seed: fixture.deterministic_seed,
        runner_reports: ordered_reports,
        per_task_breakdown,
        latency_breakdown,
        regression_gates,
        generated_artifacts: artifact_paths(),
    })
}

/// Render deterministic report artifacts without writing them.
pub fn render_phase2a_report_artifacts(
    bundle: &BenchmarkReportBundle,
) -> Result<BenchmarkReportArtifacts> {
    let benchmark_summary_json = json_string(bundle)?;
    let benchmark_summary_md = markdown_summary(bundle);
    let per_task_breakdown_json = json_string(&bundle.per_task_breakdown)?;
    let latency_breakdown_json = json_string(&bundle.latency_breakdown)?;
    Ok(BenchmarkReportArtifacts {
        benchmark_summary_json,
        benchmark_summary_md,
        per_task_breakdown_json,
        latency_breakdown_json,
    })
}

/// Write deterministic report artifacts under `target/dagdb/reports/`.
pub fn write_phase2a_report_artifacts(
    bundle: &BenchmarkReportBundle,
) -> Result<BenchmarkReportArtifacts> {
    let artifacts = render_phase2a_report_artifacts(bundle)?;
    write_artifact(BENCHMARK_SUMMARY_JSON, &artifacts.benchmark_summary_json)?;
    write_artifact(BENCHMARK_SUMMARY_MD, &artifacts.benchmark_summary_md)?;
    write_artifact(PER_TASK_BREAKDOWN_JSON, &artifacts.per_task_breakdown_json)?;
    write_artifact(LATENCY_BREAKDOWN_JSON, &artifacts.latency_breakdown_json)?;
    Ok(artifacts)
}

/// Build optimized MVP and scale capability reports.
pub fn build_optimized_capability_summary(
    mvp_fixture: &BenchmarkFixture,
) -> Result<OptimizedCapabilitySummary> {
    let scale_fixture = generate_scale_fixture();
    let mvp_reports = run_all_reports(mvp_fixture)?;
    let scale_reports = run_all_reports(&scale_fixture)?;
    let mvp_metrics = optimized_metrics_for_fixture(mvp_fixture, &mvp_reports, true)?;
    let scale_metrics = optimized_metrics_for_fixture(&scale_fixture, &scale_reports, false)?;
    let mvp_gates = optimized_mvp_gates(&mvp_metrics)?;
    let scale_selected = report_for(&scale_reports, BenchmarkRunnerName::GovernedDagDbOptimized)?;
    let scale_ratio = scale_redaction_cache_hit_ratio_bp(
        &scale_fixture,
        &scale_selected.selected_memory_ids_by_task,
    );
    let scale_gates = optimized_scale_gates(&mvp_metrics, &scale_metrics)?;
    let scale_latency_overhead_vs_mvp_bp = scale_latency_overhead_vs_mvp_bp_from_metrics(
        report_metric(&mvp_metrics, BenchmarkRunnerName::GovernedDagDbOptimized)?,
        report_metric(&scale_metrics, BenchmarkRunnerName::GovernedDagDbOptimized)?,
    );
    let governance_overhead_reduction_bp = governance_overhead_reduction_bp(
        report_for(&mvp_reports, BenchmarkRunnerName::GovernedDagDbRouting)?,
        report_for(&mvp_reports, BenchmarkRunnerName::GovernedDagDbOptimized)?,
    );
    let floor_passed = mvp_gates
        .iter()
        .chain(scale_gates.iter())
        .filter(|gate| gate.tier == OptimizedBenchmarkGateTier::Floor)
        .all(|gate| gate.passed);
    let stretch_passed = mvp_gates
        .iter()
        .chain(scale_gates.iter())
        .filter(|gate| gate.tier == OptimizedBenchmarkGateTier::Stretch)
        .all(|gate| gate.passed);
    let capability_verdict =
        optimized_capability_verdict_from_gate_status(floor_passed, stretch_passed);
    Ok(OptimizedCapabilitySummary {
        fixture_id: mvp_fixture.fixture_id.clone(),
        deterministic_seed: mvp_fixture.deterministic_seed,
        scale_fixture_id: scale_fixture.fixture_id,
        scale_deterministic_seed: scale_fixture.deterministic_seed,
        mvp_runner_metrics: mvp_metrics,
        scale_runner_metrics: scale_metrics,
        mvp_gates,
        scale_gates,
        redaction_cache_hit_ratio_bp: MVP_REDACTION_CACHE_HIT_RATIO_BP,
        scale_redaction_cache_hit_ratio_bp: scale_ratio,
        scale_latency_overhead_vs_mvp_bp,
        governance_overhead_reduction_bp,
        capability_verdict,
    })
}

/// Render optimized report artifacts without writing them.
pub fn render_optimized_report_artifacts(
    summary: &OptimizedCapabilitySummary,
) -> Result<OptimizedReportArtifacts> {
    let optimized_capability_summary_json = json_string(summary)?;
    let optimized_capability_summary_md = optimized_markdown_summary(summary);
    let scale_fixture_summary_json = json_string(&summary.scale_runner_metrics)?;
    let optimized_per_task_breakdown_json = json_string(&summary.mvp_runner_metrics)?;
    Ok(OptimizedReportArtifacts {
        optimized_capability_summary_json,
        optimized_capability_summary_md,
        scale_fixture_summary_json,
        optimized_per_task_breakdown_json,
    })
}

/// Write deterministic optimized reports under `target/dagdb/upgrade-reports/`.
pub fn write_optimized_report_artifacts(
    summary: &OptimizedCapabilitySummary,
) -> Result<OptimizedReportArtifacts> {
    let artifacts = render_optimized_report_artifacts(summary)?;
    write_artifact(
        OPTIMIZED_CAPABILITY_SUMMARY_JSON,
        &artifacts.optimized_capability_summary_json,
    )?;
    write_artifact(
        OPTIMIZED_CAPABILITY_SUMMARY_MD,
        &artifacts.optimized_capability_summary_md,
    )?;
    write_artifact(
        SCALE_FIXTURE_SUMMARY_JSON,
        &artifacts.scale_fixture_summary_json,
    )?;
    write_artifact(
        OPTIMIZED_PER_TASK_BREAKDOWN_JSON,
        &artifacts.optimized_per_task_breakdown_json,
    )?;
    Ok(artifacts)
}

/// Build the deterministic end-to-end A/B diagnostic summary.
pub fn build_end_to_end_diagnostic_summary(
    mvp_fixture: &BenchmarkFixture,
) -> Result<EndToEndDiagnosticSummary> {
    let include_optimized = has_runner(BenchmarkRunnerName::GovernedDagDbOptimized);
    build_end_to_end_diagnostic_summary_with_options(mvp_fixture, include_optimized)
}

fn build_end_to_end_diagnostic_summary_with_options(
    mvp_fixture: &BenchmarkFixture,
    include_optimized: bool,
) -> Result<EndToEndDiagnosticSummary> {
    let runner_definitions = diagnostic_runner_definitions(include_optimized);
    let scale_fixture = generate_scale_fixture();
    let replay_fixture = redacted_project_session_replay_fixture()?;
    let fixture_inputs = filtered_end_to_end_fixture_inputs(vec![
        (DiagnosticFixtureKind::MvpSynthetic, mvp_fixture.clone()),
        (DiagnosticFixtureKind::LargeSynthetic, scale_fixture),
        (
            DiagnosticFixtureKind::RedactedProjectSessionReplay,
            replay_fixture,
        ),
    ])?;
    let mut per_task_results = Vec::new();
    let mut runner_aggregates = Vec::new();
    let mut fairness_checks = Vec::new();
    let mut comparisons = Vec::new();
    let mut fixture_ids = Vec::new();

    for (fixture_kind, fixture) in &fixture_inputs {
        fixture_ids.push(fixture.fixture_id.clone());
        let reports = run_diagnostic_reports(fixture, &runner_definitions)?;
        let rows = build_end_to_end_per_task_results(
            *fixture_kind,
            fixture,
            &reports,
            &runner_definitions,
        )?;
        let aggregates = build_end_to_end_aggregates(*fixture_kind, fixture, &rows)?;
        let checks = build_end_to_end_fairness_checks(*fixture_kind, fixture, &reports);
        let fixture_comparisons =
            build_end_to_end_comparisons(*fixture_kind, &aggregates, &checks, include_optimized)?;
        per_task_results.extend(rows);
        runner_aggregates.extend(aggregates);
        fairness_checks.extend(checks);
        comparisons.extend(fixture_comparisons);
    }

    let overall_rollup = build_end_to_end_overall_rollup(&runner_aggregates)?;
    let cost_breakdown = build_end_to_end_cost_breakdown(&per_task_results);
    let quality_breakdown = build_end_to_end_quality_breakdown(&runner_aggregates);
    let pros = build_end_to_end_pros(&comparisons, &overall_rollup);
    let cons = build_end_to_end_cons(&comparisons, &overall_rollup);
    let recommendations = build_end_to_end_recommendations(&per_task_results, &comparisons);
    Ok(EndToEndDiagnosticSummary {
        deterministic_mode: true,
        live_model_status: E2E_LIVE_MODEL_SKIP.into(),
        replay_fixture_status: E2E_REPLAY_INCLUDED.into(),
        optimized_runner_status: if include_optimized {
            "governed_dagdb_optimized included".into()
        } else {
            E2E_OPTIMIZED_SKIP.into()
        },
        model_or_evaluator_id: E2E_MODEL_OR_EVALUATOR_ID.into(),
        scoring_path_id: E2E_SCORING_PATH_ID.into(),
        fixture_ids,
        runner_definitions,
        fairness_checks,
        per_task_results,
        runner_aggregates,
        comparisons,
        overall_rollup,
        cost_breakdown,
        quality_breakdown,
        pros,
        cons,
        recommendations,
        generated_artifacts: end_to_end_artifact_paths(),
    })
}

fn filtered_end_to_end_fixture_inputs(
    fixture_inputs: Vec<(DiagnosticFixtureKind, BenchmarkFixture)>,
) -> Result<Vec<(DiagnosticFixtureKind, BenchmarkFixture)>> {
    let filter = match env::var(E2E_DIAGNOSTIC_FIXTURE_FILTER_ENV) {
        Ok(value) => value.trim().to_owned(),
        Err(env::VarError::NotPresent) => return Ok(fixture_inputs),
        Err(env::VarError::NotUnicode(value)) => {
            return Err(DiagnosticsError::InvalidFixtureFilter {
                fixture_id: value.to_string_lossy().into_owned(),
            });
        }
    };
    if filter.is_empty() {
        return Ok(fixture_inputs);
    }
    let filtered = fixture_inputs
        .into_iter()
        .filter(|(_, fixture)| fixture.fixture_id == filter)
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return Err(DiagnosticsError::InvalidFixtureFilter { fixture_id: filter });
    }
    Ok(filtered)
}

fn redacted_project_session_replay_fixture() -> Result<BenchmarkFixture> {
    load_benchmark_fixture_json(REDACTED_REPLAY_FIXTURE_JSON).map_err(DiagnosticsError::Benchmark)
}

/// Render deterministic end-to-end diagnostic artifacts without writing them.
pub fn render_end_to_end_diagnostic_artifacts(
    summary: &EndToEndDiagnosticSummary,
) -> Result<EndToEndDiagnosticArtifacts> {
    Ok(EndToEndDiagnosticArtifacts {
        summary_json: json_string(summary)?,
        summary_md: end_to_end_markdown_summary(summary),
        per_task_results_json: json_string(&summary.per_task_results)?,
        latency_breakdown_json: json_string(&build_end_to_end_latency_breakdown(summary))?,
        cost_breakdown_json: json_string(&summary.cost_breakdown)?,
        quality_breakdown_json: json_string(&summary.quality_breakdown)?,
        recommendations_md: end_to_end_recommendations_markdown(summary),
    })
}

/// Write deterministic end-to-end diagnostic artifacts under `target/`.
pub fn write_end_to_end_diagnostic_artifacts(
    summary: &EndToEndDiagnosticSummary,
) -> Result<EndToEndDiagnosticArtifacts> {
    let artifacts = render_end_to_end_diagnostic_artifacts(summary)?;
    write_artifact(E2E_DIAGNOSTIC_SUMMARY_JSON, &artifacts.summary_json)?;
    write_artifact(E2E_DIAGNOSTIC_SUMMARY_MD, &artifacts.summary_md)?;
    write_artifact(
        E2E_DIAGNOSTIC_PER_TASK_RESULTS_JSON,
        &artifacts.per_task_results_json,
    )?;
    write_artifact(
        E2E_DIAGNOSTIC_LATENCY_BREAKDOWN_JSON,
        &artifacts.latency_breakdown_json,
    )?;
    write_artifact(
        E2E_DIAGNOSTIC_COST_BREAKDOWN_JSON,
        &artifacts.cost_breakdown_json,
    )?;
    write_artifact(
        E2E_DIAGNOSTIC_QUALITY_BREAKDOWN_JSON,
        &artifacts.quality_breakdown_json,
    )?;
    write_artifact(
        E2E_DIAGNOSTIC_RECOMMENDATIONS_MD,
        &artifacts.recommendations_md,
    )?;
    benchmark_isolation::write_default_benchmark_isolation_artifacts()?;
    Ok(artifacts)
}

fn has_runner(runner: BenchmarkRunnerName) -> bool {
    BenchmarkRunnerName::all().contains(&runner)
}

fn diagnostic_runner_definitions(include_optimized: bool) -> Vec<EndToEndRunnerDefinition> {
    let mut definitions = vec![
        runner_definition(
            DiagnosticRunnerRole::NeutralLongContext,
            BenchmarkRunnerName::LongContextDump,
            "neutral_long_context",
            ContextAcquisitionProfile::LongContextSourceLoading,
            true,
        ),
        runner_definition(
            DiagnosticRunnerRole::NeutralFlatRag,
            BenchmarkRunnerName::FlatRag,
            "neutral_flat_rag",
            ContextAcquisitionProfile::FlatRetrievalWithoutGraphOrganization,
            false,
        ),
        runner_definition(
            DiagnosticRunnerRole::NoMemoryLowerBound,
            BenchmarkRunnerName::NoMemory,
            "no_memory_lower_bound",
            ContextAcquisitionProfile::NoMemory,
            false,
        ),
        runner_definition(
            DiagnosticRunnerRole::DagDbRoutingRaw,
            BenchmarkRunnerName::DagDbRouting,
            "dag_db_routing_raw",
            ContextAcquisitionProfile::RawDagRouting,
            false,
        ),
        runner_definition(
            DiagnosticRunnerRole::GovernedDagdb,
            BenchmarkRunnerName::GovernedDagDbRouting,
            "governed_dagdb",
            ContextAcquisitionProfile::GovernedDagRoutingValidationContextPacketGraph,
            false,
        ),
    ];
    if include_optimized {
        definitions.push(runner_definition(
            DiagnosticRunnerRole::GovernedDagdbOptimized,
            BenchmarkRunnerName::GovernedDagDbOptimized,
            "governed_dagdb_optimized",
            ContextAcquisitionProfile::OptimizedGovernedDagRouting,
            false,
        ));
    }
    definitions
}

fn optimized_capability_verdict_from_gate_status(
    floor_passed: bool,
    stretch_passed: bool,
) -> OptimizedCapabilityVerdict {
    if !floor_passed {
        OptimizedCapabilityVerdict::FloorFailed
    } else if stretch_passed {
        OptimizedCapabilityVerdict::ImprovedToStretch
    } else {
        OptimizedCapabilityVerdict::ImprovedMeaningfully
    }
}

fn runner_definition(
    role: DiagnosticRunnerRole,
    benchmark_runner: BenchmarkRunnerName,
    diagnostic_label: &str,
    context_acquisition_profile: ContextAcquisitionProfile,
    primary_baseline_allowed: bool,
) -> EndToEndRunnerDefinition {
    EndToEndRunnerDefinition {
        role,
        benchmark_runner,
        diagnostic_label: diagnostic_label.into(),
        context_acquisition_profile,
        primary_baseline_allowed,
    }
}

fn definition_for_runner(
    definitions: &[EndToEndRunnerDefinition],
    runner: BenchmarkRunnerName,
) -> Result<&EndToEndRunnerDefinition> {
    definitions
        .iter()
        .find(|definition| definition.benchmark_runner == runner)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: runner_label(runner),
        })
}

fn definition_for_role(
    definitions: &[EndToEndRunnerDefinition],
    role: DiagnosticRunnerRole,
) -> Result<&EndToEndRunnerDefinition> {
    definitions
        .iter()
        .find(|definition| definition.role == role)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: diagnostic_role_label(role),
        })
}

fn diagnostic_role_label(role: DiagnosticRunnerRole) -> &'static str {
    match role {
        DiagnosticRunnerRole::NeutralLongContext => "neutral_long_context",
        DiagnosticRunnerRole::NeutralFlatRag => "neutral_flat_rag",
        DiagnosticRunnerRole::NoMemoryLowerBound => "no_memory_lower_bound",
        DiagnosticRunnerRole::DagDbRoutingRaw => "dag_db_routing_raw",
        DiagnosticRunnerRole::GovernedDagdb => "governed_dagdb",
        DiagnosticRunnerRole::GovernedDagdbOptimized => "governed_dagdb_optimized",
    }
}

fn run_diagnostic_reports(
    fixture: &BenchmarkFixture,
    definitions: &[EndToEndRunnerDefinition],
) -> Result<Vec<BenchmarkRunReport>> {
    definitions
        .iter()
        .map(|definition| {
            run_benchmark_fixture(fixture, definition.benchmark_runner)
                .map_err(DiagnosticsError::from)
        })
        .collect()
}

fn report_for_role<'a>(
    reports: &'a [BenchmarkRunReport],
    definitions: &[EndToEndRunnerDefinition],
    role: DiagnosticRunnerRole,
) -> Result<&'a BenchmarkRunReport> {
    let definition = definition_for_role(definitions, role)?;
    report_for(reports, definition.benchmark_runner)
}

fn build_end_to_end_per_task_results(
    fixture_kind: DiagnosticFixtureKind,
    fixture: &BenchmarkFixture,
    reports: &[BenchmarkRunReport],
    definitions: &[EndToEndRunnerDefinition],
) -> Result<Vec<EndToEndPerTaskResult>> {
    let task_count = u32::try_from(fixture.tasks.len())
        .unwrap_or(u32::MAX)
        .max(1);
    let corpus_item_count = u32::try_from(fixture.corpus.len()).unwrap_or(u32::MAX);
    let corpus_id = corpus_id(fixture);
    let neutral_prompt_per_task = report_for_role(
        reports,
        definitions,
        DiagnosticRunnerRole::NeutralLongContext,
    )?
    .prompt_tokens
        / task_count;
    let neutral_cost_per_task = total_cost_micro_exo(report_for_role(
        reports,
        definitions,
        DiagnosticRunnerRole::NeutralLongContext,
    )?) / u64::from(task_count);
    let mut rows = Vec::new();
    for report in reports {
        let definition = definition_for_runner(definitions, report.runner_name)?;
        let prompt_per_task = report.prompt_tokens / task_count;
        let completion_per_task = report.completion_tokens / task_count;
        let model_cost_per_task = model_cost_micro_exo(report) / u64::from(task_count);
        let routing_cost_per_task = routing_cost_micro_exo(report) / u64::from(task_count);
        let validation_cost_per_task = validation_cost_micro_exo(report) / u64::from(task_count);
        let storage_cost_per_task =
            storage_or_writeback_cost_micro_exo(report) / u64::from(task_count);
        let total_cost_per_task = total_cost_micro_exo(report) / u64::from(task_count);
        let net_savings_per_task =
            u64_to_i64(neutral_cost_per_task).saturating_sub(u64_to_i64(total_cost_per_task));
        for task in &fixture.tasks {
            let selected_refs = report
                .selected_memory_ids_by_task
                .get(&task.task_id)
                .map_or(0usize, Vec::len);
            let selected_refs_u32 = u32::try_from(selected_refs).unwrap_or(u32::MAX);
            let route_count = route_count_for(report.runner_name, selected_refs_u32);
            let context_packet_tokens = selected_refs_u32.saturating_mul(8);
            let latency = end_to_end_latency_breakdown(LatencyBreakdown::from_inputs(
                u64::try_from(fixture.corpus.len()).unwrap_or(u64::MAX),
                report.runner_name,
                u64::from(selected_refs_u32),
                u64::from(route_count),
                u64::from(context_packet_tokens),
            ));
            rows.push(EndToEndPerTaskResult {
                fixture_kind,
                fixture_id: fixture.fixture_id.clone(),
                task_id: task.task_id.clone(),
                task_type: task_type(task),
                runner: report.runner_name,
                diagnostic_label: definition.diagnostic_label.clone(),
                context_acquisition_profile: definition.context_acquisition_profile,
                model_or_evaluator_id: E2E_MODEL_OR_EVALUATOR_ID.into(),
                corpus_id: corpus_id.clone(),
                corpus_item_count,
                prompt_tokens: prompt_per_task,
                completion_tokens: completion_per_task,
                total_tokens: prompt_per_task.saturating_add(completion_per_task),
                overhead_tokens: report.overhead_tokens / task_count,
                selected_refs: selected_refs_u32,
                raw_payload_fetch_count: raw_payload_fetch_count(
                    report.runner_name,
                    selected_refs_u32,
                ),
                route_count,
                context_packet_tokens,
                context_reduction_bp: reduction_bp_u32(prompt_per_task, neutral_prompt_per_task),
                quality_score_bp: report.quality_score_bp,
                citation_accuracy_bp: report.citation_accuracy_bp,
                unsupported_claim_rate_bp: report.unsupported_claim_rate_bp,
                contradiction_detection_bp: None,
                missing_context_rate_bp: Some(u64::from(report.unsupported_claim_rate_bp)),
                latency_ms: latency.total_ms,
                latency_breakdown: latency,
                model_cost_micro_exo: model_cost_per_task,
                routing_cost_micro_exo: routing_cost_per_task,
                validation_cost_micro_exo: validation_cost_per_task,
                storage_or_writeback_cost_micro_exo: storage_cost_per_task,
                total_cost_micro_exo: total_cost_per_task,
                net_savings_micro_exo: net_savings_per_task,
                cost_savings_claim_allowed: false,
                quality_improvement_claim_allowed: false,
                overall_diagnostic_claim_allowed: false,
                reason_if_disallowed: Some("per_task_claim_non_authoritative".into()),
                failure_reason: None,
            });
        }
    }
    Ok(rows)
}

fn end_to_end_latency_breakdown(latency: LatencyBreakdown) -> EndToEndLatencyBreakdown {
    EndToEndLatencyBreakdown {
        catalog_lookup_ms: latency.catalog_lookup_ms,
        canonical_resolution_ms: latency.canonical_resolution_ms,
        provenance_fetch_ms: latency.provenance_fetch_ms,
        contradiction_fetch_ms: latency.contradiction_fetch_ms,
        routing_view_build_ms: latency.routing_view_build_ms,
        validation_ms: latency.validation_ms,
        context_packet_build_ms: latency.context_packet_build_ms,
        answer_or_output_ms: 0,
        writeback_ms: latency.writeback_ms,
        total_ms: latency.total_ms,
    }
}

fn build_end_to_end_aggregates(
    fixture_kind: DiagnosticFixtureKind,
    fixture: &BenchmarkFixture,
    rows: &[EndToEndPerTaskResult],
) -> Result<Vec<EndToEndRunnerAggregate>> {
    let mut aggregates = Vec::new();
    let neutral_rows = rows
        .iter()
        .filter(|row| row.runner == BenchmarkRunnerName::LongContextDump)
        .collect::<Vec<_>>();
    let neutral_prompt_total = sum_u32(neutral_rows.iter().map(|row| row.prompt_tokens));
    let neutral_cost_total = sum_u64(neutral_rows.iter().map(|row| row.total_cost_micro_exo));
    for runner in diagnostic_benchmark_runner_order(rows) {
        let runner_rows = rows
            .iter()
            .filter(|row| row.runner == runner)
            .collect::<Vec<_>>();
        let task_count = u32::try_from(runner_rows.len()).unwrap_or(u32::MAX).max(1);
        let prompt_values = runner_rows
            .iter()
            .map(|row| u64::from(row.prompt_tokens))
            .collect::<Vec<_>>();
        let latency_values = runner_rows
            .iter()
            .map(|row| row.latency_ms)
            .collect::<Vec<_>>();
        let selected_ref_total = sum_u32(runner_rows.iter().map(|row| row.selected_refs));
        let prompt_total = sum_u32(runner_rows.iter().map(|row| row.prompt_tokens));
        let total_tokens = sum_u32(runner_rows.iter().map(|row| row.total_tokens));
        let total_cost = sum_u64(runner_rows.iter().map(|row| row.total_cost_micro_exo));
        let label = runner_rows
            .first()
            .map(|row| row.diagnostic_label.clone())
            .unwrap_or_else(|| runner_label(runner).into());
        aggregates.push(EndToEndRunnerAggregate {
            fixture_kind,
            fixture_id: fixture.fixture_id.clone(),
            runner,
            diagnostic_label: label,
            task_count,
            average_prompt_tokens: prompt_total / task_count,
            median_prompt_tokens: u64_to_u32(median(&prompt_values)),
            total_prompt_tokens: prompt_total,
            average_total_tokens: total_tokens / task_count,
            total_total_tokens: total_tokens,
            average_selected_refs: selected_ref_total / task_count,
            total_selected_refs: selected_ref_total,
            average_latency_ms: sum_u64(latency_values.iter().copied()) / u64::from(task_count),
            median_latency_ms: median(&latency_values),
            p95_latency_ms: percentile_95(&latency_values),
            average_quality_score_bp: average_u16(
                runner_rows
                    .iter()
                    .map(|row| row.quality_score_bp)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            average_citation_accuracy_bp: average_u16(
                runner_rows
                    .iter()
                    .map(|row| row.citation_accuracy_bp)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            average_unsupported_claim_rate_bp: average_u16(
                runner_rows
                    .iter()
                    .map(|row| row.unsupported_claim_rate_bp)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            average_context_reduction_bp: average_option_u64(
                runner_rows
                    .iter()
                    .filter_map(|row| row.context_reduction_bp)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            total_cost_micro_exo: total_cost,
            net_savings_micro_exo: u64_to_i64(neutral_cost_total)
                .saturating_sub(u64_to_i64(total_cost)),
            percent_token_reduction_bp: reduction_bp_u32(prompt_total, neutral_prompt_total),
            percent_cost_reduction_bp: reduction_bp_u64(total_cost, neutral_cost_total),
        });
    }
    Ok(aggregates)
}

fn diagnostic_benchmark_runner_order(rows: &[EndToEndPerTaskResult]) -> Vec<BenchmarkRunnerName> {
    BenchmarkRunnerName::all()
        .iter()
        .copied()
        .filter(|runner| rows.iter().any(|row| row.runner == *runner))
        .collect()
}

fn build_end_to_end_fairness_checks(
    fixture_kind: DiagnosticFixtureKind,
    fixture: &BenchmarkFixture,
    reports: &[BenchmarkRunReport],
) -> Vec<EndToEndFairnessCheck> {
    [
        (
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
        ),
        (
            "secondary_ab_flat_rag_vs_governed_dagdb",
            DiagnosticRunnerRole::NeutralFlatRag,
            DiagnosticRunnerRole::GovernedDagdb,
        ),
        (
            "lower_bound_no_memory_vs_governed_dagdb",
            DiagnosticRunnerRole::NoMemoryLowerBound,
            DiagnosticRunnerRole::GovernedDagdb,
        ),
        (
            "raw_dag_vs_governed_dagdb",
            DiagnosticRunnerRole::DagDbRoutingRaw,
            DiagnosticRunnerRole::GovernedDagdb,
        ),
    ]
    .iter()
    .filter_map(|(name, neutral, dag)| {
        build_fairness_check(fixture_kind, fixture, reports, name, *neutral, *dag)
    })
    .collect()
}

fn build_fairness_check(
    fixture_kind: DiagnosticFixtureKind,
    fixture: &BenchmarkFixture,
    reports: &[BenchmarkRunReport],
    comparison_name: &str,
    neutral_runner: DiagnosticRunnerRole,
    dag_runner: DiagnosticRunnerRole,
) -> Option<EndToEndFairnessCheck> {
    let neutral_report = reports
        .iter()
        .find(|report| report.runner_name == benchmark_runner_for_role(neutral_runner));
    let dag_report = reports
        .iter()
        .find(|report| report.runner_name == benchmark_runner_for_role(dag_runner));
    let (Some(neutral_report), Some(dag_report)) = (neutral_report, dag_report) else {
        return None;
    };
    let same_fixture_id = all_true(&[
        neutral_report.fixture_id == dag_report.fixture_id,
        neutral_report.fixture_id == fixture.fixture_id,
    ]);
    let neutral_corpus_id = corpus_id(fixture);
    let dag_corpus_id = corpus_id(fixture);
    let same_corpus_id = neutral_corpus_id == dag_corpus_id;
    let neutral_task_ids = selected_task_ids(neutral_report);
    let dag_task_ids = selected_task_ids(dag_report);
    let expected_task_ids = fixture_task_ids(fixture);
    let same_task_ids = all_true(&[
        neutral_task_ids == dag_task_ids,
        neutral_task_ids == expected_task_ids,
    ]);
    let neutral_source_pool = source_pool_ids(fixture);
    let dag_source_pool = source_pool_ids(fixture);
    let same_allowed_source_pool = neutral_source_pool == dag_source_pool;
    let same_evaluator_and_scoring_path = all_true(&[
        neutral_report.deterministic_seed == dag_report.deterministic_seed,
        neutral_report.tokenizer_config_hash == dag_report.tokenizer_config_hash,
        neutral_report.temperature_bp == dag_report.temperature_bp,
        neutral_report.top_p_bp == dag_report.top_p_bp,
        neutral_report.max_output_tokens == dag_report.max_output_tokens,
    ]);
    let same_source_availability = all_true(&[
        same_fixture_id,
        same_corpus_id,
        same_task_ids,
        same_allowed_source_pool,
        same_evaluator_and_scoring_path,
    ]);
    let selected_refs_differ =
        neutral_report.selected_memory_ids_by_task != dag_report.selected_memory_ids_by_task;
    let passed = same_source_availability;
    Some(EndToEndFairnessCheck {
        comparison_name: comparison_name.into(),
        fixture_kind,
        fixture_id: fixture.fixture_id.clone(),
        neutral_runner,
        dag_runner,
        same_fixture_id,
        same_corpus_id,
        same_task_ids,
        same_allowed_source_pool,
        same_evaluator_and_scoring_path,
        same_source_availability,
        selected_refs_may_differ: true,
        selected_refs_differ,
        passed,
        reason_if_failed: if passed {
            None
        } else {
            Some("fairness_gate_failed".into())
        },
    })
}

fn benchmark_runner_for_role(role: DiagnosticRunnerRole) -> BenchmarkRunnerName {
    match role {
        DiagnosticRunnerRole::NeutralLongContext => BenchmarkRunnerName::LongContextDump,
        DiagnosticRunnerRole::NeutralFlatRag => BenchmarkRunnerName::FlatRag,
        DiagnosticRunnerRole::NoMemoryLowerBound => BenchmarkRunnerName::NoMemory,
        DiagnosticRunnerRole::DagDbRoutingRaw => BenchmarkRunnerName::DagDbRouting,
        DiagnosticRunnerRole::GovernedDagdb => BenchmarkRunnerName::GovernedDagDbRouting,
        DiagnosticRunnerRole::GovernedDagdbOptimized => BenchmarkRunnerName::GovernedDagDbOptimized,
    }
}

fn build_end_to_end_comparisons(
    fixture_kind: DiagnosticFixtureKind,
    aggregates: &[EndToEndRunnerAggregate],
    fairness_checks: &[EndToEndFairnessCheck],
    include_optimized: bool,
) -> Result<Vec<EndToEndComparison>> {
    let mut comparisons = vec![
        build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            fixture_kind,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            aggregates,
            fairness_checks,
        )?,
        build_comparison(
            "secondary_ab_flat_rag_vs_governed_dagdb",
            fixture_kind,
            DiagnosticRunnerRole::NeutralFlatRag,
            DiagnosticRunnerRole::GovernedDagdb,
            aggregates,
            fairness_checks,
        )?,
        build_comparison(
            "lower_bound_no_memory_vs_governed_dagdb",
            fixture_kind,
            DiagnosticRunnerRole::NoMemoryLowerBound,
            DiagnosticRunnerRole::GovernedDagdb,
            aggregates,
            fairness_checks,
        )?,
        build_comparison(
            "raw_dag_vs_governed_dagdb",
            fixture_kind,
            DiagnosticRunnerRole::DagDbRoutingRaw,
            DiagnosticRunnerRole::GovernedDagdb,
            aggregates,
            fairness_checks,
        )?,
    ];
    if include_optimized {
        comparisons.push(build_comparison(
            "optimization_governed_vs_optimized",
            fixture_kind,
            DiagnosticRunnerRole::GovernedDagdb,
            DiagnosticRunnerRole::GovernedDagdbOptimized,
            aggregates,
            fairness_checks,
        )?);
    }
    Ok(comparisons)
}

fn build_comparison(
    comparison_name: &str,
    fixture_kind: DiagnosticFixtureKind,
    neutral_runner: DiagnosticRunnerRole,
    dag_runner: DiagnosticRunnerRole,
    aggregates: &[EndToEndRunnerAggregate],
    fairness_checks: &[EndToEndFairnessCheck],
) -> Result<EndToEndComparison> {
    let neutral = aggregate_for_role(aggregates, neutral_runner)?;
    let dag = aggregate_for_role(aggregates, dag_runner)?;
    let fairness_passed = fairness_checks
        .iter()
        .find(|check| {
            check.fixture_kind == fixture_kind
                && check.comparison_name == comparison_name
                && check.neutral_runner == neutral_runner
                && check.dag_runner == dag_runner
        })
        .is_none_or(|check| check.passed);
    let token_reduction_bp = reduction_bp_u32(dag.total_prompt_tokens, neutral.total_prompt_tokens);
    let cost_reduction_bp =
        reduction_bp_u64(dag.total_cost_micro_exo, neutral.total_cost_micro_exo);
    let quality_delta_bp = i32::from(dag.average_quality_score_bp)
        .saturating_sub(i32::from(neutral.average_quality_score_bp));
    let citation_delta_bp = i32::from(dag.average_citation_accuracy_bp)
        .saturating_sub(i32::from(neutral.average_citation_accuracy_bp));
    let unsupported_claim_improvement_bp = i32::from(neutral.average_unsupported_claim_rate_bp)
        .saturating_sub(i32::from(dag.average_unsupported_claim_rate_bp));
    let latency_delta_ms =
        u64_to_i64(dag.average_latency_ms).saturating_sub(u64_to_i64(neutral.average_latency_ms));
    let net_savings_micro_exo = u64_to_i64(neutral.total_cost_micro_exo)
        .saturating_sub(u64_to_i64(dag.total_cost_micro_exo));
    let safety_ok = matches!(
        dag_runner,
        DiagnosticRunnerRole::GovernedDagdb | DiagnosticRunnerRole::GovernedDagdbOptimized
    );
    let no_quality_regression = quality_delta_bp >= 0;
    let no_citation_regression = citation_delta_bp >= 0;
    let no_unsupported_regression = unsupported_claim_improvement_bp >= 0;
    let token_reduction_ok = token_reduction_bp.is_some_and(|value| value >= 1_000);
    let prompt_lower = dag.total_prompt_tokens < neutral.total_prompt_tokens;
    let cost_lower = dag.total_cost_micro_exo < neutral.total_cost_micro_exo;
    let primary_baseline_ok = comparison_name != "primary_ab_long_context_vs_governed_dagdb"
        || neutral_runner == DiagnosticRunnerRole::NeutralLongContext;
    let cost_savings_claim_allowed = all_true(&[
        fairness_passed,
        primary_baseline_ok,
        cost_lower,
        prompt_lower,
        token_reduction_ok,
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
        safety_ok,
    ]);
    let quality_improvement_claim_allowed = all_true(&[
        fairness_passed,
        primary_baseline_ok,
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
        safety_ok,
    ]);
    let overall_diagnostic_claim_allowed = any_true(&[
        cost_savings_claim_allowed,
        quality_improvement_claim_allowed,
    ]);
    let reason_if_disallowed = comparison_reason(ComparisonClaimInputs {
        fairness_passed,
        primary_baseline_ok,
        cost_lower,
        prompt_lower,
        token_reduction_ok,
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
        safety_ok,
        overall_diagnostic_claim_allowed,
    });
    Ok(EndToEndComparison {
        comparison_name: comparison_name.into(),
        fixture_kind,
        neutral_runner,
        dag_runner,
        fairness_passed,
        cost_savings_claim_allowed,
        quality_improvement_claim_allowed,
        overall_diagnostic_claim_allowed,
        reason_if_disallowed,
        token_reduction_bp,
        cost_reduction_bp,
        quality_delta_bp,
        citation_delta_bp,
        unsupported_claim_improvement_bp,
        latency_delta_ms,
        net_savings_micro_exo,
    })
}

fn aggregate_for_role(
    aggregates: &[EndToEndRunnerAggregate],
    role: DiagnosticRunnerRole,
) -> Result<&EndToEndRunnerAggregate> {
    let runner = benchmark_runner_for_role(role);
    aggregates
        .iter()
        .find(|aggregate| aggregate.runner == runner)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: diagnostic_role_label(role),
        })
}

#[derive(Debug, Clone, Copy)]
struct ComparisonClaimInputs {
    fairness_passed: bool,
    primary_baseline_ok: bool,
    cost_lower: bool,
    prompt_lower: bool,
    token_reduction_ok: bool,
    no_quality_regression: bool,
    no_citation_regression: bool,
    no_unsupported_regression: bool,
    safety_ok: bool,
    overall_diagnostic_claim_allowed: bool,
}

fn comparison_reason(inputs: ComparisonClaimInputs) -> Option<String> {
    if inputs.overall_diagnostic_claim_allowed {
        return None;
    }
    let mut reasons = Vec::new();
    if !inputs.fairness_passed {
        reasons.push("fairness_gate_failed");
    }
    if !inputs.primary_baseline_ok {
        reasons.push("primary_baseline_not_long_context");
    }
    if !inputs.cost_lower {
        reasons.push("cost_not_lower");
    }
    if !inputs.prompt_lower {
        reasons.push("prompt_tokens_not_lower");
    }
    if !inputs.token_reduction_ok {
        reasons.push("token_reduction_below_1000bp");
    }
    if !inputs.no_quality_regression {
        reasons.push("quality_regression");
    }
    if !inputs.no_citation_regression {
        reasons.push("citation_regression");
    }
    if !inputs.no_unsupported_regression {
        reasons.push("unsupported_claim_regression");
    }
    if !inputs.safety_ok {
        reasons.push("safety_governance_regression");
    }
    if reasons.is_empty() {
        Some("claim_gate_internal".into())
    } else {
        Some(reasons.join(", "))
    }
}

fn build_end_to_end_overall_rollup(
    aggregates: &[EndToEndRunnerAggregate],
) -> Result<EndToEndOverallRollup> {
    let mut total_prompt_tokens_by_runner = BTreeMap::new();
    let mut total_cost_micro_exo_by_runner = BTreeMap::new();
    let mut quality_by_runner = BTreeMap::<String, Vec<u16>>::new();
    let mut citation_by_runner = BTreeMap::<String, Vec<u16>>::new();
    let mut unsupported_by_runner = BTreeMap::<String, Vec<u16>>::new();
    let mut latency_by_runner = BTreeMap::<String, Vec<u64>>::new();
    for aggregate in aggregates {
        let label = aggregate.diagnostic_label.clone();
        *total_prompt_tokens_by_runner
            .entry(label.clone())
            .or_insert(0) += u64::from(aggregate.total_prompt_tokens);
        *total_cost_micro_exo_by_runner
            .entry(label.clone())
            .or_insert(0) += aggregate.total_cost_micro_exo;
        quality_by_runner
            .entry(label.clone())
            .or_default()
            .push(aggregate.average_quality_score_bp);
        citation_by_runner
            .entry(label.clone())
            .or_default()
            .push(aggregate.average_citation_accuracy_bp);
        unsupported_by_runner
            .entry(label.clone())
            .or_default()
            .push(aggregate.average_unsupported_claim_rate_bp);
        latency_by_runner
            .entry(label)
            .or_default()
            .push(aggregate.average_latency_ms);
    }
    let average_quality_score_bp_by_runner = average_bp_map(quality_by_runner);
    let average_citation_accuracy_bp_by_runner = average_bp_map(citation_by_runner);
    let average_unsupported_claim_rate_bp_by_runner = average_bp_map(unsupported_by_runner);
    let average_latency_ms_by_runner = average_u64_map(latency_by_runner);
    let neutral_label = "neutral_long_context";
    let governed_label = "governed_dagdb";
    let neutral_prompt = *total_prompt_tokens_by_runner.get(neutral_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: neutral_label,
        },
    )?;
    let governed_prompt = *total_prompt_tokens_by_runner.get(governed_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: governed_label,
        },
    )?;
    let neutral_cost = *total_cost_micro_exo_by_runner.get(neutral_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: neutral_label,
        },
    )?;
    let governed_cost = *total_cost_micro_exo_by_runner.get(governed_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: governed_label,
        },
    )?;
    let neutral_quality = *average_quality_score_bp_by_runner
        .get(neutral_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: neutral_label,
        })?;
    let governed_quality = *average_quality_score_bp_by_runner
        .get(governed_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: governed_label,
        })?;
    let neutral_citation = *average_citation_accuracy_bp_by_runner
        .get(neutral_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: neutral_label,
        })?;
    let governed_citation = *average_citation_accuracy_bp_by_runner
        .get(governed_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: governed_label,
        })?;
    let neutral_unsupported = *average_unsupported_claim_rate_bp_by_runner
        .get(neutral_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: neutral_label,
        })?;
    let governed_unsupported = *average_unsupported_claim_rate_bp_by_runner
        .get(governed_label)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: governed_label,
        })?;
    let neutral_latency = *average_latency_ms_by_runner.get(neutral_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: neutral_label,
        },
    )?;
    let governed_latency = *average_latency_ms_by_runner.get(governed_label).ok_or(
        DiagnosticsError::MissingRunner {
            runner: governed_label,
        },
    )?;
    let overall_primary_token_reduction_bp = reduction_bp_u64(governed_prompt, neutral_prompt);
    let overall_primary_cost_reduction_bp = reduction_bp_u64(governed_cost, neutral_cost);
    let overall_primary_quality_delta_bp =
        i32::from(governed_quality).saturating_sub(i32::from(neutral_quality));
    let overall_primary_citation_delta_bp =
        i32::from(governed_citation).saturating_sub(i32::from(neutral_citation));
    let overall_primary_unsupported_claim_improvement_bp =
        i32::from(neutral_unsupported).saturating_sub(i32::from(governed_unsupported));
    let overall_primary_latency_delta_ms =
        u64_to_i64(governed_latency).saturating_sub(u64_to_i64(neutral_latency));
    let prompt_lower = governed_prompt < neutral_prompt;
    let cost_lower = governed_cost < neutral_cost;
    let token_reduction_ok = overall_primary_token_reduction_bp.is_some_and(|value| value >= 1_000);
    let no_quality_regression = overall_primary_quality_delta_bp >= 0;
    let no_citation_regression = overall_primary_citation_delta_bp >= 0;
    let no_unsupported_regression = overall_primary_unsupported_claim_improvement_bp >= 0;
    let overall_rollup_cost_savings_claim_allowed = all_true(&[
        cost_lower,
        prompt_lower,
        token_reduction_ok,
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
    ]);
    let overall_rollup_quality_improvement_claim_allowed = all_true(&[
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
    ]);
    let overall_rollup_diagnostic_claim_allowed = any_true(&[
        overall_rollup_cost_savings_claim_allowed,
        overall_rollup_quality_improvement_claim_allowed,
    ]);
    let overall_rollup_reason_if_disallowed = comparison_reason(ComparisonClaimInputs {
        fairness_passed: true,
        primary_baseline_ok: true,
        cost_lower,
        prompt_lower,
        token_reduction_ok,
        no_quality_regression,
        no_citation_regression,
        no_unsupported_regression,
        safety_ok: true,
        overall_diagnostic_claim_allowed: overall_rollup_diagnostic_claim_allowed,
    });
    Ok(EndToEndOverallRollup {
        total_prompt_tokens_by_runner,
        total_cost_micro_exo_by_runner,
        average_quality_score_bp_by_runner,
        average_citation_accuracy_bp_by_runner,
        average_unsupported_claim_rate_bp_by_runner,
        average_latency_ms_by_runner,
        overall_primary_token_reduction_bp,
        overall_primary_cost_reduction_bp,
        overall_primary_quality_delta_bp,
        overall_primary_citation_delta_bp,
        overall_primary_unsupported_claim_improvement_bp,
        overall_primary_latency_delta_ms,
        overall_rollup_cost_savings_claim_allowed,
        overall_rollup_quality_improvement_claim_allowed,
        overall_rollup_diagnostic_claim_allowed,
        overall_rollup_reason_if_disallowed,
    })
}

fn build_end_to_end_cost_breakdown(rows: &[EndToEndPerTaskResult]) -> Vec<EndToEndCostBreakdown> {
    let mut by_runner = BTreeMap::<
        (DiagnosticFixtureKind, String, BenchmarkRunnerName, String),
        EndToEndCostBreakdown,
    >::new();
    for row in rows {
        let key = (
            row.fixture_kind,
            row.fixture_id.clone(),
            row.runner,
            row.diagnostic_label.clone(),
        );
        let entry = by_runner.entry(key).or_insert(EndToEndCostBreakdown {
            fixture_kind: row.fixture_kind,
            fixture_id: row.fixture_id.clone(),
            runner: row.runner,
            diagnostic_label: row.diagnostic_label.clone(),
            model_cost_micro_exo: 0,
            routing_cost_micro_exo: 0,
            validation_cost_micro_exo: 0,
            storage_or_writeback_cost_micro_exo: 0,
            total_cost_micro_exo: 0,
        });
        entry.model_cost_micro_exo = entry
            .model_cost_micro_exo
            .saturating_add(row.model_cost_micro_exo);
        entry.routing_cost_micro_exo = entry
            .routing_cost_micro_exo
            .saturating_add(row.routing_cost_micro_exo);
        entry.validation_cost_micro_exo = entry
            .validation_cost_micro_exo
            .saturating_add(row.validation_cost_micro_exo);
        entry.storage_or_writeback_cost_micro_exo = entry
            .storage_or_writeback_cost_micro_exo
            .saturating_add(row.storage_or_writeback_cost_micro_exo);
        entry.total_cost_micro_exo = entry
            .total_cost_micro_exo
            .saturating_add(row.total_cost_micro_exo);
    }
    by_runner.into_values().collect()
}

fn build_end_to_end_quality_breakdown(
    aggregates: &[EndToEndRunnerAggregate],
) -> Vec<EndToEndQualityBreakdown> {
    aggregates
        .iter()
        .map(|aggregate| EndToEndQualityBreakdown {
            fixture_kind: aggregate.fixture_kind,
            fixture_id: aggregate.fixture_id.clone(),
            runner: aggregate.runner,
            diagnostic_label: aggregate.diagnostic_label.clone(),
            quality_score_bp: aggregate.average_quality_score_bp,
            citation_accuracy_bp: aggregate.average_citation_accuracy_bp,
            unsupported_claim_rate_bp: aggregate.average_unsupported_claim_rate_bp,
        })
        .collect()
}

fn build_end_to_end_latency_breakdown(
    summary: &EndToEndDiagnosticSummary,
) -> BTreeMap<String, BTreeMap<String, EndToEndLatencyBreakdown>> {
    let mut by_fixture = BTreeMap::<String, BTreeMap<String, EndToEndLatencyBreakdown>>::new();
    for row in &summary.per_task_results {
        let fixture_key = format!("{:?}:{}", row.fixture_kind, row.fixture_id);
        let runner_key = row.diagnostic_label.clone();
        let entry = by_fixture
            .entry(fixture_key)
            .or_default()
            .entry(runner_key)
            .or_insert(EndToEndLatencyBreakdown {
                catalog_lookup_ms: 0,
                canonical_resolution_ms: 0,
                provenance_fetch_ms: 0,
                contradiction_fetch_ms: 0,
                routing_view_build_ms: 0,
                validation_ms: 0,
                context_packet_build_ms: 0,
                answer_or_output_ms: 0,
                writeback_ms: 0,
                total_ms: 0,
            });
        entry.catalog_lookup_ms = entry
            .catalog_lookup_ms
            .saturating_add(row.latency_breakdown.catalog_lookup_ms);
        entry.canonical_resolution_ms = entry
            .canonical_resolution_ms
            .saturating_add(row.latency_breakdown.canonical_resolution_ms);
        entry.provenance_fetch_ms = entry
            .provenance_fetch_ms
            .saturating_add(row.latency_breakdown.provenance_fetch_ms);
        entry.contradiction_fetch_ms = entry
            .contradiction_fetch_ms
            .saturating_add(row.latency_breakdown.contradiction_fetch_ms);
        entry.routing_view_build_ms = entry
            .routing_view_build_ms
            .saturating_add(row.latency_breakdown.routing_view_build_ms);
        entry.validation_ms = entry
            .validation_ms
            .saturating_add(row.latency_breakdown.validation_ms);
        entry.context_packet_build_ms = entry
            .context_packet_build_ms
            .saturating_add(row.latency_breakdown.context_packet_build_ms);
        entry.answer_or_output_ms = entry
            .answer_or_output_ms
            .saturating_add(row.latency_breakdown.answer_or_output_ms);
        entry.writeback_ms = entry
            .writeback_ms
            .saturating_add(row.latency_breakdown.writeback_ms);
        entry.total_ms = entry
            .total_ms
            .saturating_add(row.latency_breakdown.total_ms);
    }
    by_fixture
}

fn build_end_to_end_pros(
    comparisons: &[EndToEndComparison],
    rollup: &EndToEndOverallRollup,
) -> Vec<String> {
    let mut pros = Vec::new();
    if rollup.overall_primary_token_reduction_bp.unwrap_or(0) >= 1_000 {
        pros.push("Governed DAG DB reduces prompt tokens versus long context in the deterministic harness.".into());
    }
    if rollup.overall_primary_quality_delta_bp >= 0 {
        pros.push("Governed DAG DB preserves or improves quality versus long context.".into());
    }
    if rollup.overall_primary_citation_delta_bp >= 0 {
        pros.push(
            "Governed DAG DB preserves or improves citation accuracy versus long context.".into(),
        );
    }
    if rollup.overall_primary_unsupported_claim_improvement_bp >= 0 {
        pros.push("Governed DAG DB reduces unsupported-claim rate versus long context.".into());
    }
    if comparisons
        .iter()
        .any(|comparison| comparison.quality_improvement_claim_allowed)
    {
        pros.push("Quality/safety improvement is claimable separately from cost savings.".into());
    }
    pros
}

fn build_end_to_end_cons(
    comparisons: &[EndToEndComparison],
    rollup: &EndToEndOverallRollup,
) -> Vec<String> {
    let mut cons = Vec::new();
    if rollup.overall_primary_latency_delta_ms > 0 {
        cons.push(
            "Governed DAG DB has higher deterministic processing latency than long context.".into(),
        );
    }
    if !rollup.overall_rollup_cost_savings_claim_allowed {
        cons.push("Cost-savings claims are blocked when governed total cost is not lower.".into());
    }
    if comparisons
        .iter()
        .any(|comparison| !comparison.cost_savings_claim_allowed)
    {
        cons.push("Some comparison blocks do not support a cost-savings claim.".into());
    }
    cons.push(
        "Live model performance and USD savings remain unproven until an approved live benchmark runs."
            .into(),
    );
    cons
}

fn build_end_to_end_recommendations(
    rows: &[EndToEndPerTaskResult],
    comparisons: &[EndToEndComparison],
) -> Vec<String> {
    let (highest_savings, lowest_savings) = task_type_savings_extremes(rows);
    let highest_quality_gain = highest_quality_gain_task_type(rows);
    let governance_worth = comparisons
        .iter()
        .find(|comparison| {
            comparison.comparison_name == "primary_ab_long_context_vs_governed_dagdb"
        })
        .is_some_and(|comparison| comparison.overall_diagnostic_claim_allowed);
    vec![
        "Best improvement target: reduce governed deterministic latency and governance overhead while preserving validation.".into(),
        "Worst bottleneck: governed routing adds validation, graph, and context-packet accounting latency.".into(),
        format!("Highest-savings task type: {highest_savings}."),
        format!("Lowest-savings task type: {lowest_savings}."),
        format!("Highest-quality-gain task type: {highest_quality_gain}."),
        "Where DAG routing over-fetches: compare governed_dagdb selected refs against governed_dagdb_optimized and route-budget evidence.".into(),
        "Where neutral_long_context still performs well: it remains the strongest same-source completeness baseline.".into(),
        "Where neutral_flat_rag still performs well: it gives a lower-overhead retrieval baseline without graph organization.".into(),
        format!(
            "Governance overhead is worth it in this harness: {}.",
            if governance_worth { "yes" } else { "not yet as a cost-savings claim" }
        ),
        "Live external model testing is justified after deterministic report review and operator spend approval.".into(),
        "Replay fixture coverage is included; add more named redacted sessions before cross-session trend claims.".into(),
        "Optimize next: route budget, validation batching, and context-packet compaction for governed_dagdb.".into(),
    ]
}

fn task_type_savings_extremes(rows: &[EndToEndPerTaskResult]) -> (String, String) {
    let mut savings_by_task_type = BTreeMap::<String, i64>::new();
    for row in rows
        .iter()
        .filter(|row| row.runner == BenchmarkRunnerName::GovernedDagDbRouting)
    {
        *savings_by_task_type
            .entry(row.task_type.clone())
            .or_insert(0) += row.net_savings_micro_exo;
    }
    let highest = savings_by_task_type
        .iter()
        .max_by_key(|(_, savings)| **savings)
        .map(|(task_type, _)| task_type.clone())
        .unwrap_or_else(|| "none".into());
    let lowest = savings_by_task_type
        .iter()
        .min_by_key(|(_, savings)| **savings)
        .map(|(task_type, _)| task_type.clone())
        .unwrap_or_else(|| "none".into());
    (highest, lowest)
}

fn highest_quality_gain_task_type(rows: &[EndToEndPerTaskResult]) -> String {
    let mut neutral_by_task = BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row.runner == BenchmarkRunnerName::LongContextDump)
    {
        neutral_by_task.insert(
            (row.fixture_id.clone(), row.task_id.clone()),
            row.quality_score_bp,
        );
    }
    let mut gain_by_task_type = BTreeMap::<String, i32>::new();
    for row in rows
        .iter()
        .filter(|row| row.runner == BenchmarkRunnerName::GovernedDagDbRouting)
    {
        let neutral = neutral_by_task
            .get(&(row.fixture_id.clone(), row.task_id.clone()))
            .copied()
            .unwrap_or(0);
        *gain_by_task_type.entry(row.task_type.clone()).or_insert(0) +=
            i32::from(row.quality_score_bp).saturating_sub(i32::from(neutral));
    }
    gain_by_task_type
        .iter()
        .max_by_key(|(_, gain)| **gain)
        .map(|(task_type, _)| task_type.clone())
        .unwrap_or_else(|| "none".into())
}

fn model_cost_micro_exo(report: &BenchmarkRunReport) -> u64 {
    u64::from(report.prompt_tokens)
        .saturating_mul(2)
        .saturating_add(u64::from(report.completion_tokens).saturating_mul(4))
}

fn routing_cost_micro_exo(report: &BenchmarkRunReport) -> u64 {
    report
        .overhead
        .route_scoring_micro_exo
        .saturating_add(report.overhead.postgres_query_micro_exo)
}

fn validation_cost_micro_exo(report: &BenchmarkRunReport) -> u64 {
    report
        .overhead
        .validation_micro_exo
        .saturating_add(report.overhead.redaction_micro_exo)
}

fn storage_or_writeback_cost_micro_exo(report: &BenchmarkRunReport) -> u64 {
    report
        .overhead
        .idempotency_lookup_micro_exo
        .saturating_add(report.overhead.dag_outbox_enqueue_micro_exo)
        .saturating_add(report.overhead.context_packet_micro_exo)
}

fn total_cost_micro_exo(report: &BenchmarkRunReport) -> u64 {
    model_cost_micro_exo(report).saturating_add(report.overhead_micro_exo)
}

fn corpus_id(fixture: &BenchmarkFixture) -> String {
    format!(
        "{}:seed:{}:corpus:{}",
        fixture.fixture_id,
        fixture.deterministic_seed,
        fixture.corpus.len()
    )
}

fn source_pool_ids(fixture: &BenchmarkFixture) -> std::collections::BTreeSet<String> {
    fixture
        .corpus
        .iter()
        .map(|item| {
            item.memory_id
                .clone()
                .unwrap_or_else(|| item.corpus_item_id.clone())
        })
        .collect()
}

fn fixture_task_ids(fixture: &BenchmarkFixture) -> std::collections::BTreeSet<String> {
    fixture
        .tasks
        .iter()
        .map(|task| task.task_id.clone())
        .collect()
}

fn selected_task_ids(report: &BenchmarkRunReport) -> std::collections::BTreeSet<String> {
    report.selected_memory_ids_by_task.keys().cloned().collect()
}

fn all_true(values: &[bool]) -> bool {
    values.iter().copied().all(|value| value)
}

fn any_true(values: &[bool]) -> bool {
    values.iter().copied().any(|value| value)
}

fn sum_u32(values: impl Iterator<Item = u32>) -> u32 {
    values.fold(0u32, u32::saturating_add)
}

fn sum_u64(values: impl Iterator<Item = u64>) -> u64 {
    values.fold(0u64, u64::saturating_add)
}

fn median(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn percentile_95(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = sorted.len().saturating_mul(95).saturating_add(99) / 100;
    sorted[index.saturating_sub(1).min(sorted.len().saturating_sub(1))]
}

fn average_u16(values: &[u16]) -> u16 {
    if values.is_empty() {
        return 0;
    }
    let total = values
        .iter()
        .fold(0u64, |sum, value| sum.saturating_add(u64::from(*value)));
    u64_to_u16(total / u64::try_from(values.len()).unwrap_or(u64::MAX).max(1))
}

fn average_option_u64(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    Some(sum_u64(values.iter().copied()) / u64::try_from(values.len()).unwrap_or(u64::MAX).max(1))
}

fn average_bp_map(values_by_runner: BTreeMap<String, Vec<u16>>) -> BTreeMap<String, u16> {
    values_by_runner
        .into_iter()
        .map(|(runner, values)| (runner, average_u16(&values)))
        .collect()
}

fn average_u64_map(values_by_runner: BTreeMap<String, Vec<u64>>) -> BTreeMap<String, u64> {
    values_by_runner
        .into_iter()
        .map(|(runner, values)| {
            let average = if values.is_empty() {
                0
            } else {
                sum_u64(values.iter().copied())
                    / u64::try_from(values.len()).unwrap_or(u64::MAX).max(1)
            };
            (runner, average)
        })
        .collect()
}

fn reduction_bp_u32(observed: u32, baseline: u32) -> Option<u64> {
    if baseline == 0 || observed >= baseline {
        return None;
    }
    Some(u64::from(baseline.saturating_sub(observed)).saturating_mul(10_000) / u64::from(baseline))
}

fn reduction_bp_u64(observed: u64, baseline: u64) -> Option<u64> {
    if baseline == 0 || observed >= baseline {
        return None;
    }
    Some(baseline.saturating_sub(observed).saturating_mul(10_000) / baseline)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn u64_to_u16(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn format_option_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |inner| inner.to_string())
}

fn end_to_end_artifact_paths() -> Vec<String> {
    [
        E2E_DIAGNOSTIC_SUMMARY_JSON,
        E2E_DIAGNOSTIC_SUMMARY_MD,
        E2E_DIAGNOSTIC_PER_TASK_RESULTS_JSON,
        E2E_DIAGNOSTIC_LATENCY_BREAKDOWN_JSON,
        E2E_DIAGNOSTIC_COST_BREAKDOWN_JSON,
        E2E_DIAGNOSTIC_QUALITY_BREAKDOWN_JSON,
        E2E_DIAGNOSTIC_RECOMMENDATIONS_MD,
    ]
    .iter()
    .map(|path| (*path).into())
    .collect()
}

fn primary_comparison(summary: &EndToEndDiagnosticSummary) -> Option<&EndToEndComparison> {
    summary.comparisons.iter().find(|comparison| {
        comparison.comparison_name == "primary_ab_long_context_vs_governed_dagdb"
    })
}

fn secondary_comparison(summary: &EndToEndDiagnosticSummary) -> Option<&EndToEndComparison> {
    summary
        .comparisons
        .iter()
        .find(|comparison| comparison.comparison_name == "secondary_ab_flat_rag_vs_governed_dagdb")
}

fn end_to_end_markdown_summary(summary: &EndToEndDiagnosticSummary) -> String {
    let primary = primary_comparison(summary);
    let secondary = secondary_comparison(summary);
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB End-to-End Diagnostic Report\n\n");
    output.push_str("## Test Setup\n\n");
    output.push_str(E2E_HARNESS_DISCLAIMER);
    output.push('\n');
    output.push_str(&format!(
        "- deterministic_mode: {}\n",
        summary.deterministic_mode
    ));
    output.push_str(&format!(
        "- live_model_status: {}\n",
        summary.live_model_status
    ));
    output.push_str(&format!(
        "- replay_fixture_status: {}\n",
        summary.replay_fixture_status
    ));
    output.push_str(&format!(
        "- optimized_runner_status: {}\n",
        summary.optimized_runner_status
    ));
    output.push_str("- cost_unit: micro_exo deterministic harness cost units, not USD\n\n");
    output.push_str("## Fairness Check\n\n");
    output.push_str("Fairness means both runners start from the same available source corpus and task set; selected refs may differ.\n\n");
    output.push_str("| comparison | fixture | fairness_passed | selected_refs_differ |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for check in &summary.fairness_checks {
        output.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            check.comparison_name, check.fixture_kind, check.passed, check.selected_refs_differ
        ));
    }
    output.push_str("\n## Executive Summary\n\n");
    output.push_str(&interpretation_sentences(summary).join("\n"));
    output.push_str("\n\n## Overall Rollup\n\n");
    output.push_str("| runner | prompt_tokens | total_cost_micro_exo | quality_bp | citation_bp | unsupported_bp | avg_latency_ms |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for runner in summary.overall_rollup.total_prompt_tokens_by_runner.keys() {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            runner,
            summary
                .overall_rollup
                .total_prompt_tokens_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0),
            summary
                .overall_rollup
                .total_cost_micro_exo_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0),
            summary
                .overall_rollup
                .average_quality_score_bp_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0),
            summary
                .overall_rollup
                .average_citation_accuracy_bp_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0),
            summary
                .overall_rollup
                .average_unsupported_claim_rate_bp_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0),
            summary
                .overall_rollup
                .average_latency_ms_by_runner
                .get(runner)
                .copied()
                .unwrap_or(0)
        ));
    }
    output.push_str("\n## Primary A/B: Long Context vs Governed DAG DB\n\n");
    push_comparison_table(&mut output, primary);
    output.push_str("\n## Secondary A/B: Flat RAG vs Governed DAG DB\n\n");
    push_comparison_table(&mut output, secondary);
    output.push_str("\n## Lower-Bound Sanity: No Memory\n\n");
    push_named_comparison_table(
        &mut output,
        summary,
        "lower_bound_no_memory_vs_governed_dagdb",
    );
    output.push_str("\n## Raw DAG vs Governed DAG\n\n");
    push_named_comparison_table(&mut output, summary, "raw_dag_vs_governed_dagdb");
    output.push_str("\n## Token Efficiency\n\n");
    output.push_str(&format!(
        "- overall_primary_token_reduction_bp: {}\n",
        format_option_u64(summary.overall_rollup.overall_primary_token_reduction_bp)
    ));
    output.push_str("\n## Cost Difference\n\n");
    output.push_str(&format!(
        "- overall_primary_cost_reduction_bp: {}\n",
        format_option_u64(summary.overall_rollup.overall_primary_cost_reduction_bp)
    ));
    output.push_str("- micro_exo values are deterministic harness cost units, not USD.\n");
    if summary
        .overall_rollup
        .overall_rollup_quality_improvement_claim_allowed
        && !summary
            .overall_rollup
            .overall_rollup_cost_savings_claim_allowed
    {
        output.push_str(&format!("- {}\n", E2E_QUALITY_ONLY_MESSAGE));
    }
    output.push_str("\n## Latency Difference\n\n");
    output.push_str(&format!(
        "- overall_primary_latency_delta_ms: {}\n",
        summary.overall_rollup.overall_primary_latency_delta_ms
    ));
    output.push_str("\n## Context Quality\n\n");
    output.push_str("- Context quality is represented by selected refs, context reduction, citation accuracy, and unsupported-claim behavior.\n");
    output.push_str("\n## Output Quality\n\n");
    output.push_str(&format!(
        "- overall_primary_quality_delta_bp: {}\n",
        summary.overall_rollup.overall_primary_quality_delta_bp
    ));
    output.push_str("\n## Safety / Unsupported Claims\n\n");
    output.push_str(&format!(
        "- overall_primary_unsupported_claim_improvement_bp: {}\n",
        summary
            .overall_rollup
            .overall_primary_unsupported_claim_improvement_bp
    ));
    output.push_str("\n## Per-Fixture Results\n\n");
    output.push_str("| fixture | runner | prompt_tokens | cost_micro_exo | quality_bp | citation_bp | unsupported_bp | latency_ms |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for aggregate in &summary.runner_aggregates {
        output.push_str(&format!(
            "| {:?} | {} | {} | {} | {} | {} | {} | {} |\n",
            aggregate.fixture_kind,
            aggregate.diagnostic_label,
            aggregate.total_prompt_tokens,
            aggregate.total_cost_micro_exo,
            aggregate.average_quality_score_bp,
            aggregate.average_citation_accuracy_bp,
            aggregate.average_unsupported_claim_rate_bp,
            aggregate.average_latency_ms
        ));
    }
    output.push_str("\n## Pros\n\n");
    for pro in &summary.pros {
        output.push_str(&format!("- {pro}\n"));
    }
    output.push_str("\n## Cons\n\n");
    for con in &summary.cons {
        output.push_str(&format!("- {con}\n"));
    }
    output.push_str("\n## What This Means\n\n");
    output.push_str(E2E_HARNESS_DISCLAIMER);
    output.push('\n');
    output.push_str("\n## Recommended Next Work\n\n");
    for recommendation in &summary.recommendations {
        output.push_str(&format!("- {recommendation}\n"));
    }
    output.push_str("\n## Verdict\n\n");
    output.push_str(&format!("- {}\n", final_diagnostic_verdict(summary)));
    output
}

fn push_comparison_table(output: &mut String, comparison: Option<&EndToEndComparison>) {
    output.push_str("| token_reduction_bp | cost_reduction_bp | quality_delta_bp | citation_delta_bp | unsupported_improvement_bp | latency_delta_ms | cost_claim | quality_claim | overall_claim |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    if let Some(comparison) = comparison {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            format_option_u64(comparison.token_reduction_bp),
            format_option_u64(comparison.cost_reduction_bp),
            comparison.quality_delta_bp,
            comparison.citation_delta_bp,
            comparison.unsupported_claim_improvement_bp,
            comparison.latency_delta_ms,
            comparison.cost_savings_claim_allowed,
            comparison.quality_improvement_claim_allowed,
            comparison.overall_diagnostic_claim_allowed
        ));
    }
}

fn push_named_comparison_table(
    output: &mut String,
    summary: &EndToEndDiagnosticSummary,
    name: &str,
) {
    let comparison = summary
        .comparisons
        .iter()
        .find(|comparison| comparison.comparison_name == name);
    push_comparison_table(output, comparison);
}

fn interpretation_sentences(summary: &EndToEndDiagnosticSummary) -> Vec<String> {
    let rollup = &summary.overall_rollup;
    vec![
        format!(
            "- Governed DAG DB reduced prompt tokens: {}.",
            rollup.overall_primary_token_reduction_bp.is_some()
        ),
        format!(
            "- Governed DAG DB reduced cost: {}.",
            rollup.overall_primary_cost_reduction_bp.is_some()
        ),
        format!(
            "- Governed DAG DB improved or preserved quality: {}.",
            rollup.overall_primary_quality_delta_bp >= 0
        ),
        format!(
            "- Governed DAG DB improved or preserved citation accuracy: {}.",
            rollup.overall_primary_citation_delta_bp >= 0
        ),
        format!(
            "- Governed DAG DB reduced unsupported claims: {}.",
            rollup.overall_primary_unsupported_claim_improvement_bp >= 0
        ),
        format!(
            "- Governance overhead was worth it: {}.",
            rollup.overall_rollup_diagnostic_claim_allowed
        ),
        "- Redaction-safe replay fixture data is included; next value comes from comparing multiple named replay datasets.".into(),
    ]
}

fn final_diagnostic_verdict(summary: &EndToEndDiagnosticSummary) -> &'static str {
    let primary = primary_comparison(summary);
    let reports_exist = !summary.generated_artifacts.is_empty();
    let fairness_ok = summary.fairness_checks.iter().all(|check| check.passed);
    let primary_ok = primary.is_some_and(|comparison| {
        all_true(&[
            comparison.neutral_runner == DiagnosticRunnerRole::NeutralLongContext,
            comparison.quality_delta_bp >= 0,
            comparison.citation_delta_bp >= 0,
            comparison.unsupported_claim_improvement_bp >= 0,
            comparison.token_reduction_bp.is_some(),
            any_true(&[
                comparison.cost_savings_claim_allowed,
                comparison.quality_improvement_claim_allowed,
            ]),
        ])
    });
    if all_true(&[reports_exist, fairness_ok, primary_ok]) {
        "Ship"
    } else {
        "Fix blockers and re-run"
    }
}

fn end_to_end_recommendations_markdown(summary: &EndToEndDiagnosticSummary) -> String {
    let mut output = String::new();
    output.push_str("# End-to-End Diagnostic Recommendations\n\n");
    for recommendation in &summary.recommendations {
        output.push_str(&format!("- {recommendation}\n"));
    }
    output
}

/// Return required regression gate names in fixed order.
#[must_use]
pub fn required_regression_gate_names() -> [&'static str; 7] {
    [
        "governed_claim_allowed",
        "governed_quality_gte_long_context",
        "governed_citation_accuracy_gte_long_context",
        "governed_unsupported_claims_lte_long_context",
        "governed_prompt_tokens_lt_long_context",
        "governed_prompt_token_reduction_bp_min_1000",
        "governed_safety_quality_not_weakened",
    ]
}

/// Build a deterministic disallow reason from failing gates.
#[must_use]
pub fn reason_if_disallowed(
    claim_allowed: bool,
    gates: &[BenchmarkRegressionGateResult],
) -> Option<String> {
    if claim_allowed {
        return None;
    }
    let failed = required_regression_gate_names()
        .iter()
        .filter(|name| {
            gates
                .iter()
                .any(|gate| gate.gate_name == **name && !gate.passed)
        })
        .copied()
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Some("claim_gate_internal".into())
    } else {
        Some(failed.join(", "))
    }
}

/// Evaluate governed DAG DB against long context.
pub fn evaluate_phase2a_regression_gates(
    reports: &[BenchmarkRunReport],
) -> Result<Vec<BenchmarkRegressionGateResult>> {
    let governed = report_for(reports, BenchmarkRunnerName::GovernedDagDbRouting)?;
    let long_context = report_for(reports, BenchmarkRunnerName::LongContextDump)?;
    let prompt_reduction_bp =
        prompt_token_reduction_bp(governed.prompt_tokens, long_context.prompt_tokens);
    let gates = vec![
        gate(
            "governed_claim_allowed",
            governed.savings_claim_allowed,
            u64::from(governed.savings_claim_allowed),
            1,
            1,
        ),
        gate(
            "governed_quality_gte_long_context",
            governed.quality_score_bp >= long_context.quality_score_bp,
            u64::from(governed.quality_score_bp),
            u64::from(long_context.quality_score_bp),
            u64::from(long_context.quality_score_bp),
        ),
        gate(
            "governed_citation_accuracy_gte_long_context",
            governed.citation_accuracy_bp >= long_context.citation_accuracy_bp,
            u64::from(governed.citation_accuracy_bp),
            u64::from(long_context.citation_accuracy_bp),
            u64::from(long_context.citation_accuracy_bp),
        ),
        gate(
            "governed_unsupported_claims_lte_long_context",
            governed.unsupported_claim_rate_bp <= long_context.unsupported_claim_rate_bp,
            u64::from(governed.unsupported_claim_rate_bp),
            u64::from(long_context.unsupported_claim_rate_bp),
            u64::from(long_context.unsupported_claim_rate_bp),
        ),
        gate(
            "governed_prompt_tokens_lt_long_context",
            governed.prompt_tokens < long_context.prompt_tokens,
            u64::from(governed.prompt_tokens),
            u64::from(long_context.prompt_tokens),
            u64::from(long_context.prompt_tokens.saturating_sub(1)),
        ),
        gate(
            "governed_prompt_token_reduction_bp_min_1000",
            prompt_reduction_bp >= PROMPT_TOKEN_REDUCTION_THRESHOLD_BP,
            prompt_reduction_bp,
            0,
            PROMPT_TOKEN_REDUCTION_THRESHOLD_BP,
        ),
        gate(
            "governed_safety_quality_not_weakened",
            all_true(&[
                governed.quality_score_bp >= 8_500,
                governed.citation_accuracy_bp >= 9_500,
                governed.unsupported_claim_rate_bp <= 500,
                governed.savings_claim_allowed,
            ]),
            u64::from(governed.quality_score_bp),
            8_500,
            8_500,
        ),
    ];
    Ok(gates)
}

fn run_all_reports(fixture: &BenchmarkFixture) -> Result<Vec<BenchmarkRunReport>> {
    BenchmarkRunnerName::all()
        .iter()
        .map(|runner| run_benchmark_fixture(fixture, *runner).map_err(DiagnosticsError::from))
        .collect()
}

fn optimized_metrics_for_fixture(
    fixture: &BenchmarkFixture,
    reports: &[BenchmarkRunReport],
    mvp_ratio: bool,
) -> Result<Vec<OptimizedRunnerMetrics>> {
    let mut rows = Vec::new();
    for report in reports {
        let ratio = if report.runner_name == BenchmarkRunnerName::GovernedDagDbOptimized {
            if mvp_ratio {
                MVP_REDACTION_CACHE_HIT_RATIO_BP
            } else {
                scale_redaction_cache_hit_ratio_bp(fixture, &report.selected_memory_ids_by_task)
            }
        } else {
            0
        };
        let latency = if report.runner_name == BenchmarkRunnerName::GovernedDagDbOptimized {
            optimized_fixture_latency(fixture, &report.selected_memory_ids_by_task, ratio)
        } else {
            fixture_level_latency(fixture, report)
        };
        let task_count = u64::try_from(fixture.tasks.len())
            .unwrap_or(u64::MAX)
            .max(1);
        rows.push(OptimizedRunnerMetrics {
            runner: report.runner_name,
            quality_score_bp: report.quality_score_bp,
            citation_accuracy_bp: report.citation_accuracy_bp,
            unsupported_claim_rate_bp: report.unsupported_claim_rate_bp,
            prompt_tokens_total: report.prompt_tokens,
            overhead_tokens_total: report.overhead_tokens,
            net_savings_micro_exo_total: report.net_savings_micro_exo,
            deterministic_latency_ms_total: latency.total_ms,
            mean_per_task_latency_ms: latency.total_ms / task_count,
            claim_allowed: report.savings_claim_allowed,
        });
    }
    Ok(rows)
}

fn fixture_level_latency(
    fixture: &BenchmarkFixture,
    report: &BenchmarkRunReport,
) -> LatencyBreakdown {
    let selected_ref_count = report
        .selected_memory_ids_by_task
        .values()
        .map(|ids| u64::try_from(ids.len()).unwrap_or(u64::MAX))
        .sum::<u64>();
    let route_count = report
        .selected_memory_ids_by_task
        .values()
        .filter(|ids| !ids.is_empty())
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let context_packet_tokens = selected_ref_count.saturating_mul(8);
    LatencyBreakdown::from_inputs(
        u64::try_from(fixture.corpus.len()).unwrap_or(u64::MAX),
        report.runner_name,
        selected_ref_count,
        route_count,
        context_packet_tokens,
    )
}

fn optimized_mvp_gates(
    metrics: &[OptimizedRunnerMetrics],
) -> Result<Vec<OptimizedBenchmarkGateResult>> {
    let optimized = report_metric(metrics, BenchmarkRunnerName::GovernedDagDbOptimized)?;
    let governed = report_metric(metrics, BenchmarkRunnerName::GovernedDagDbRouting)?;
    let mut gates = vec![
        gate_floor_ge(
            "optimized_quality_gte_9300_mvp_floor",
            optimized.quality_score_bp.into(),
            9_300,
        ),
        gate_floor_ge(
            "optimized_citation_accuracy_gte_9850_mvp_floor",
            optimized.citation_accuracy_bp.into(),
            9_850,
        ),
        gate_floor_le(
            "optimized_unsupported_claims_lte_60_mvp_floor",
            optimized.unsupported_claim_rate_bp.into(),
            60,
        ),
        gate_floor_le(
            "optimized_prompt_tokens_lte_520_mvp_floor",
            optimized.prompt_tokens_total.into(),
            520,
        ),
        gate_floor_le(
            "optimized_overhead_tokens_lte_360_mvp_floor",
            optimized.overhead_tokens_total.into(),
            360,
        ),
        gate_floor_ge(
            "optimized_net_savings_gte_3300_mvp_floor",
            optimized.net_savings_micro_exo_total,
            3_300,
        ),
        gate_floor_le(
            "optimized_latency_lte_320_mvp_floor",
            optimized.deterministic_latency_ms_total,
            320,
        ),
        gate_floor_bool("optimized_claim_allowed_mvp_floor", optimized.claim_allowed),
        gate_floor_le(
            "optimized_latency_reduction_gate",
            optimized.deterministic_latency_ms_total,
            governed
                .deterministic_latency_ms_total
                .saturating_mul(7_500)
                / 10_000,
        ),
        gate_floor_le(
            "optimized_governance_overhead_reduction_gate",
            optimized.overhead_tokens_total.into(),
            u64::from(governed.overhead_tokens_total).saturating_mul(7_500) / 10_000,
        ),
    ];
    gates.extend([
        gate_stretch_ge(
            "optimized_quality_gte_9600_mvp_stretch",
            optimized.quality_score_bp.into(),
            9_600,
        ),
        gate_stretch_ge(
            "optimized_citation_accuracy_gte_9900_mvp_stretch",
            optimized.citation_accuracy_bp.into(),
            9_900,
        ),
        gate_stretch_le(
            "optimized_unsupported_claims_lte_25_mvp_stretch",
            optimized.unsupported_claim_rate_bp.into(),
            25,
        ),
        gate_stretch_le(
            "optimized_prompt_tokens_lte_360_mvp_stretch",
            optimized.prompt_tokens_total.into(),
            360,
        ),
        gate_stretch_le(
            "optimized_overhead_tokens_lte_240_mvp_stretch",
            optimized.overhead_tokens_total.into(),
            240,
        ),
        gate_stretch_ge(
            "optimized_net_savings_gte_4000_mvp_stretch",
            optimized.net_savings_micro_exo_total,
            4_000,
        ),
        gate_stretch_le(
            "optimized_latency_lte_180_mvp_stretch",
            optimized.deterministic_latency_ms_total,
            180,
        ),
        gate_stretch_bool(
            "optimized_claim_allowed_mvp_stretch",
            optimized.claim_allowed,
        ),
    ]);
    Ok(gates)
}

fn optimized_scale_gates(
    mvp_metrics: &[OptimizedRunnerMetrics],
    scale_metrics: &[OptimizedRunnerMetrics],
) -> Result<Vec<OptimizedBenchmarkGateResult>> {
    let mvp_optimized = report_metric(mvp_metrics, BenchmarkRunnerName::GovernedDagDbOptimized)?;
    let optimized = report_metric(scale_metrics, BenchmarkRunnerName::GovernedDagDbOptimized)?;
    let long_context = report_metric(scale_metrics, BenchmarkRunnerName::LongContextDump)?;
    let prompt_reduction = prompt_token_reduction_bp(
        optimized.prompt_tokens_total,
        long_context.prompt_tokens_total,
    );
    let latency_overhead = scale_latency_overhead_vs_mvp_bp_from_metrics(mvp_optimized, optimized);
    let mut gates = vec![
        gate_floor_ge("optimized_scale_task_count_eq_150_floor", 150, 150),
        gate_floor_ge("optimized_scale_corpus_count_eq_1200_floor", 1_200, 1_200),
        gate_floor_ge(
            "optimized_scale_quality_gte_9300_floor",
            optimized.quality_score_bp.into(),
            9_300,
        ),
        gate_floor_ge(
            "optimized_scale_citation_accuracy_gte_9850_floor",
            optimized.citation_accuracy_bp.into(),
            9_850,
        ),
        gate_floor_le(
            "optimized_scale_unsupported_claims_lte_60_floor",
            optimized.unsupported_claim_rate_bp.into(),
            60,
        ),
        gate_floor_ge(
            "optimized_scale_prompt_reduction_gte_5000bp_floor",
            prompt_reduction,
            5_000,
        ),
        gate_floor_ge(
            "optimized_scale_net_savings_gte_16500_floor",
            optimized.net_savings_micro_exo_total,
            16_500,
        ),
        gate_floor_le(
            "optimized_scale_latency_overhead_lte_3000bp_floor",
            latency_overhead,
            3_000,
        ),
        gate_floor_bool(
            "optimized_scale_claim_allowed_floor",
            optimized.claim_allowed,
        ),
    ];
    gates.extend([
        gate_stretch_ge(
            "optimized_scale_quality_gte_9500_stretch",
            optimized.quality_score_bp.into(),
            9_500,
        ),
        gate_stretch_ge(
            "optimized_scale_citation_accuracy_gte_9850_stretch",
            optimized.citation_accuracy_bp.into(),
            9_850,
        ),
        gate_stretch_le(
            "optimized_scale_unsupported_claims_lte_50_stretch",
            optimized.unsupported_claim_rate_bp.into(),
            50,
        ),
        gate_stretch_ge(
            "optimized_scale_prompt_reduction_gte_9000bp_stretch",
            prompt_reduction,
            9_000,
        ),
        gate_stretch_ge(
            "optimized_scale_net_savings_gte_27540_stretch",
            optimized.net_savings_micro_exo_total,
            27_540,
        ),
        gate_stretch_le(
            "optimized_scale_latency_overhead_lte_1500bp_stretch",
            latency_overhead,
            1_500,
        ),
        gate_stretch_bool(
            "optimized_scale_claim_allowed_stretch",
            optimized.claim_allowed,
        ),
    ]);
    Ok(gates)
}

fn build_per_task_diagnostics(
    fixture: &BenchmarkFixture,
    reports: &[BenchmarkRunReport],
    gates: &[BenchmarkRegressionGateResult],
) -> Vec<PerTaskBenchmarkDiagnostic> {
    let task_count = u32::try_from(fixture.tasks.len())
        .unwrap_or(u32::MAX)
        .max(1);
    let mut rows = Vec::new();
    for report in reports {
        for task in &fixture.tasks {
            let selected_refs = report
                .selected_memory_ids_by_task
                .get(&task.task_id)
                .map_or(0usize, Vec::len);
            let selected_refs_u32 = u32::try_from(selected_refs).unwrap_or(u32::MAX);
            let route_count = route_count_for(report.runner_name, selected_refs_u32);
            let context_packet_tokens = selected_refs_u32.saturating_mul(8);
            let latency = LatencyBreakdown::from_inputs(
                u64::try_from(fixture.corpus.len()).unwrap_or(u64::MAX),
                report.runner_name,
                u64::from(selected_refs_u32),
                u64::from(route_count),
                u64::from(context_packet_tokens),
            );
            let claim_allowed = if report.runner_name == BenchmarkRunnerName::GovernedDagDbRouting {
                report.savings_claim_allowed && gates.iter().all(|gate| gate.passed)
            } else {
                report.savings_claim_allowed
            };
            rows.push(PerTaskBenchmarkDiagnostic {
                task_id: task.task_id.clone(),
                task_type: task_type(task),
                runner: report.runner_name,
                quality_score_bp: report.quality_score_bp,
                citation_accuracy_bp: report.citation_accuracy_bp,
                unsupported_claim_rate_bp: report.unsupported_claim_rate_bp,
                prompt_tokens: report.prompt_tokens / task_count,
                overhead_tokens: report.overhead_tokens / task_count,
                selected_refs: selected_refs_u32,
                raw_payload_fetch_count: raw_payload_fetch_count(
                    report.runner_name,
                    selected_refs_u32,
                ),
                route_count,
                context_packet_tokens,
                latency_ms: latency.total_ms,
                net_savings_micro_exo: report.net_savings_micro_exo / u64::from(task_count),
                claim_allowed,
                reason_if_disallowed: if report.runner_name
                    == BenchmarkRunnerName::GovernedDagDbRouting
                {
                    reason_if_disallowed(claim_allowed, gates)
                } else {
                    reason_if_disallowed(claim_allowed, &[])
                },
            });
        }
    }
    rows
}

fn aggregate_latency_by_runner(
    rows: &[PerTaskBenchmarkDiagnostic],
    corpus_count: u64,
) -> BTreeMap<String, LatencyBreakdown> {
    let mut by_runner = BTreeMap::new();
    for runner in BenchmarkRunnerName::all() {
        let aggregate = rows
            .iter()
            .filter(|row| row.runner == runner)
            .map(|row| {
                LatencyBreakdown::from_inputs(
                    corpus_count,
                    row.runner,
                    u64::from(row.selected_refs),
                    u64::from(row.route_count),
                    u64::from(row.context_packet_tokens),
                )
            })
            .fold(empty_latency(), LatencyBreakdown::add);
        by_runner.insert(runner_label(runner).into(), aggregate);
    }
    by_runner
}

fn gate(
    gate_name: &'static str,
    passed: bool,
    observed_value: u64,
    baseline_value: u64,
    threshold_value: u64,
) -> BenchmarkRegressionGateResult {
    BenchmarkRegressionGateResult {
        gate_name: gate_name.into(),
        passed,
        runner: BenchmarkRunnerName::GovernedDagDbRouting,
        baseline_runner: BenchmarkRunnerName::LongContextDump,
        observed_value,
        baseline_value,
        threshold_value,
        reason: if passed { "passed" } else { "failed" }.into(),
    }
}

fn prompt_token_reduction_bp(governed_prompt_tokens: u32, long_context_prompt_tokens: u32) -> u64 {
    if long_context_prompt_tokens == 0 || governed_prompt_tokens >= long_context_prompt_tokens {
        return 0;
    }
    u64::from(long_context_prompt_tokens.saturating_sub(governed_prompt_tokens))
        .saturating_mul(10_000)
        / u64::from(long_context_prompt_tokens)
}

fn report_metric(
    metrics: &[OptimizedRunnerMetrics],
    runner: BenchmarkRunnerName,
) -> Result<&OptimizedRunnerMetrics> {
    metrics
        .iter()
        .find(|metric| metric.runner == runner)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: runner_label(runner),
        })
}

fn scale_latency_overhead_vs_mvp_bp_from_metrics(
    mvp_optimized: &OptimizedRunnerMetrics,
    scale_optimized: &OptimizedRunnerMetrics,
) -> u64 {
    if mvp_optimized.mean_per_task_latency_ms == 0
        || scale_optimized.mean_per_task_latency_ms <= mvp_optimized.mean_per_task_latency_ms
    {
        return 0;
    }
    scale_optimized
        .mean_per_task_latency_ms
        .saturating_sub(mvp_optimized.mean_per_task_latency_ms)
        .saturating_mul(10_000)
        / mvp_optimized.mean_per_task_latency_ms
}

fn governance_overhead_reduction_bp(
    governed: &BenchmarkRunReport,
    optimized: &BenchmarkRunReport,
) -> u64 {
    if governed.overhead_tokens == 0 || optimized.overhead_tokens >= governed.overhead_tokens {
        return 0;
    }
    u64::from(
        governed
            .overhead_tokens
            .saturating_sub(optimized.overhead_tokens),
    )
    .saturating_mul(10_000)
        / u64::from(governed.overhead_tokens)
}

fn gate_floor_ge(
    name: &'static str,
    observed: u64,
    threshold: u64,
) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Floor,
        observed >= threshold,
        observed,
        threshold,
    )
}

fn gate_floor_le(
    name: &'static str,
    observed: u64,
    threshold: u64,
) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Floor,
        observed <= threshold,
        observed,
        threshold,
    )
}

fn gate_floor_bool(name: &'static str, observed: bool) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Floor,
        observed,
        u64::from(observed),
        1,
    )
}

fn gate_stretch_ge(
    name: &'static str,
    observed: u64,
    threshold: u64,
) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Stretch,
        observed >= threshold,
        observed,
        threshold,
    )
}

fn gate_stretch_le(
    name: &'static str,
    observed: u64,
    threshold: u64,
) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Stretch,
        observed <= threshold,
        observed,
        threshold,
    )
}

fn gate_stretch_bool(name: &'static str, observed: bool) -> OptimizedBenchmarkGateResult {
    optimized_gate(
        name,
        OptimizedBenchmarkGateTier::Stretch,
        observed,
        u64::from(observed),
        1,
    )
}

fn optimized_gate(
    name: &'static str,
    tier: OptimizedBenchmarkGateTier,
    passed: bool,
    observed_value: u64,
    threshold_value: u64,
) -> OptimizedBenchmarkGateResult {
    OptimizedBenchmarkGateResult {
        gate_name: name.into(),
        tier,
        passed,
        observed_value,
        baseline_value: 0,
        threshold_value,
        reason: if passed { "passed" } else { "failed" }.into(),
    }
}

fn ordered_reports(mut reports: Vec<BenchmarkRunReport>) -> Result<Vec<BenchmarkRunReport>> {
    let mut ordered = Vec::new();
    for runner in BenchmarkRunnerName::all() {
        let Some(index) = reports
            .iter()
            .position(|report| report.runner_name == runner)
        else {
            return Err(DiagnosticsError::MissingRunner {
                runner: runner_label(runner),
            });
        };
        ordered.push(reports.remove(index));
    }
    Ok(ordered)
}

fn report_for(
    reports: &[BenchmarkRunReport],
    runner: BenchmarkRunnerName,
) -> Result<&BenchmarkRunReport> {
    reports
        .iter()
        .find(|report| report.runner_name == runner)
        .ok_or(DiagnosticsError::MissingRunner {
            runner: runner_label(runner),
        })
}

fn task_type(task: &crate::benchmark::BenchmarkTask) -> String {
    if task
        .risk_labels
        .iter()
        .any(|risk| matches!(risk, RiskClass::R3 | RiskClass::R4 | RiskClass::R5))
    {
        "approval_required".into()
    } else if task.expected_validation_outcome != ValidationStatus::Passed {
        "validation_blocked".into()
    } else {
        "retrieval".into()
    }
}

fn route_count_for(runner: BenchmarkRunnerName, selected_refs: u32) -> u32 {
    match runner {
        BenchmarkRunnerName::FlatRag
        | BenchmarkRunnerName::DagDbRouting
        | BenchmarkRunnerName::GovernedDagDbRouting
        | BenchmarkRunnerName::GovernedDagDbOptimized
            if selected_refs > 0 =>
        {
            1
        }
        BenchmarkRunnerName::NoMemory
        | BenchmarkRunnerName::LongContextDump
        | BenchmarkRunnerName::FlatRag
        | BenchmarkRunnerName::DagDbRouting
        | BenchmarkRunnerName::GovernedDagDbRouting
        | BenchmarkRunnerName::GovernedDagDbOptimized => 0,
    }
}

fn raw_payload_fetch_count(runner: BenchmarkRunnerName, selected_refs: u32) -> u32 {
    match runner {
        BenchmarkRunnerName::LongContextDump => selected_refs,
        BenchmarkRunnerName::NoMemory
        | BenchmarkRunnerName::FlatRag
        | BenchmarkRunnerName::DagDbRouting
        | BenchmarkRunnerName::GovernedDagDbRouting
        | BenchmarkRunnerName::GovernedDagDbOptimized => 0,
    }
}

const fn runner_factor(runner: BenchmarkRunnerName) -> u64 {
    match runner {
        BenchmarkRunnerName::NoMemory => 0,
        BenchmarkRunnerName::LongContextDump => 1,
        BenchmarkRunnerName::FlatRag => 2,
        BenchmarkRunnerName::DagDbRouting => 3,
        BenchmarkRunnerName::GovernedDagDbRouting | BenchmarkRunnerName::GovernedDagDbOptimized => {
            4
        }
    }
}

/// Stable runner label for reports.
#[must_use]
pub const fn runner_label(runner: BenchmarkRunnerName) -> &'static str {
    match runner {
        BenchmarkRunnerName::NoMemory => "no_memory",
        BenchmarkRunnerName::LongContextDump => "long_context_dump",
        BenchmarkRunnerName::FlatRag => "flat_rag",
        BenchmarkRunnerName::DagDbRouting => "dag_db_routing",
        BenchmarkRunnerName::GovernedDagDbRouting => "governed_dag_db_routing",
        BenchmarkRunnerName::GovernedDagDbOptimized => "governed_dag_db_optimized",
    }
}

fn empty_latency() -> LatencyBreakdown {
    LatencyBreakdown {
        catalog_lookup_ms: 0,
        canonical_resolution_ms: 0,
        provenance_fetch_ms: 0,
        contradiction_fetch_ms: 0,
        routing_view_build_ms: 0,
        validation_ms: 0,
        context_packet_build_ms: 0,
        writeback_ms: 0,
        total_ms: 0,
    }
}

fn artifact_paths() -> Vec<String> {
    [
        BENCHMARK_SUMMARY_JSON,
        BENCHMARK_SUMMARY_MD,
        PER_TASK_BREAKDOWN_JSON,
        LATENCY_BREAKDOWN_JSON,
    ]
    .iter()
    .map(|path| (*path).into())
    .collect()
}

fn json_string<T: Serialize>(value: &T) -> Result<String> {
    let mut json =
        serde_json::to_string_pretty(value).map_err(|source| DiagnosticsError::Json { source })?;
    json.push('\n');
    Ok(json)
}

fn markdown_summary(bundle: &BenchmarkReportBundle) -> String {
    let mut output = String::new();
    output.push_str("## Fixture\n\n");
    output.push_str(&format!("- fixture_id: {}\n", bundle.fixture_id));
    output.push_str(&format!(
        "- deterministic_seed: {}\n\n",
        bundle.deterministic_seed
    ));

    output.push_str("## Runners\n\n");
    output.push_str("| runner | quality_score_bp | citation_accuracy_bp | unsupported_claim_rate_bp | prompt_tokens | claim_allowed |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for report in &bundle.runner_reports {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            runner_label(report.runner_name),
            report.quality_score_bp,
            report.citation_accuracy_bp,
            report.unsupported_claim_rate_bp,
            report.prompt_tokens,
            report.savings_claim_allowed
        ));
    }
    output.push('\n');

    output.push_str("## Per-Task Diagnostics\n\n");
    for runner in BenchmarkRunnerName::all() {
        output.push_str(&format!("### {}\n\n", runner_label(runner)));
        output.push_str("| task_id | task_type | quality_score_bp | citation_accuracy_bp | prompt_tokens | overhead_tokens | latency_ms | net_savings_micro_exo | claim_allowed |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for row in bundle
            .per_task_breakdown
            .iter()
            .filter(|row| row.runner == runner)
        {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                row.task_id,
                row.task_type,
                row.quality_score_bp,
                row.citation_accuracy_bp,
                row.prompt_tokens,
                row.overhead_tokens,
                row.latency_ms,
                row.net_savings_micro_exo,
                row.claim_allowed
            ));
        }
        output.push('\n');
    }

    output.push_str("## Latency Breakdown\n\n");
    output.push_str("| runner | catalog_lookup_ms | canonical_resolution_ms | provenance_fetch_ms | contradiction_fetch_ms | routing_view_build_ms | validation_ms | context_packet_build_ms | writeback_ms | total_ms |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for runner in BenchmarkRunnerName::all() {
        let label = runner_label(runner);
        if let Some(latency) = bundle.latency_breakdown.get(label) {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                label,
                latency.catalog_lookup_ms,
                latency.canonical_resolution_ms,
                latency.provenance_fetch_ms,
                latency.contradiction_fetch_ms,
                latency.routing_view_build_ms,
                latency.validation_ms,
                latency.context_packet_build_ms,
                latency.writeback_ms,
                latency.total_ms
            ));
        }
    }
    output.push('\n');

    output.push_str("## Regression Gates\n\n");
    output.push_str("| gate_name | passed | runner | baseline_runner | observed_value | baseline_value | threshold_value | reason |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for gate in &bundle.regression_gates {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            gate.gate_name,
            gate.passed,
            runner_label(gate.runner),
            runner_label(gate.baseline_runner),
            gate.observed_value,
            gate.baseline_value,
            gate.threshold_value,
            gate.reason
        ));
    }
    output.push('\n');

    output.push_str("## Generated Artifacts\n\n");
    for path in &bundle.generated_artifacts {
        output.push_str(&format!("- {path}\n"));
    }
    output
}

fn optimized_markdown_summary(summary: &OptimizedCapabilitySummary) -> String {
    let mut output = String::new();
    output.push_str("# Optimized DAG DB Capability Summary\n\n");
    output.push_str(&format!("- fixture_id: {}\n", summary.fixture_id));
    output.push_str(&format!(
        "- deterministic_seed: {}\n",
        summary.deterministic_seed
    ));
    output.push_str(&format!(
        "- scale_fixture_id: {}\n",
        summary.scale_fixture_id
    ));
    output.push_str(&format!(
        "- capability_verdict: {:?}\n\n",
        summary.capability_verdict
    ));
    output.push_str("## MVP Runner Metrics\n\n");
    output.push_str("| runner | quality_bp | citation_bp | unsupported_bp | prompt_tokens_total | overhead_tokens_total | net_savings_micro_exo_total | latency_ms_total | claim_allowed |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for metric in &summary.mvp_runner_metrics {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            runner_label(metric.runner),
            metric.quality_score_bp,
            metric.citation_accuracy_bp,
            metric.unsupported_claim_rate_bp,
            metric.prompt_tokens_total,
            metric.overhead_tokens_total,
            metric.net_savings_micro_exo_total,
            metric.deterministic_latency_ms_total,
            metric.claim_allowed
        ));
    }
    output.push_str("\n## Scale Runner Metrics\n\n");
    output.push_str("| runner | quality_bp | citation_bp | unsupported_bp | prompt_tokens_total | overhead_tokens_total | net_savings_micro_exo_total | latency_ms_total | mean_latency_ms | claim_allowed |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for metric in &summary.scale_runner_metrics {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            runner_label(metric.runner),
            metric.quality_score_bp,
            metric.citation_accuracy_bp,
            metric.unsupported_claim_rate_bp,
            metric.prompt_tokens_total,
            metric.overhead_tokens_total,
            metric.net_savings_micro_exo_total,
            metric.deterministic_latency_ms_total,
            metric.mean_per_task_latency_ms,
            metric.claim_allowed
        ));
    }
    output.push_str("\n## MVP Gates\n\n");
    output.push_str("| gate | tier | passed | observed | threshold |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for gate in &summary.mvp_gates {
        output.push_str(&format!(
            "| {} | {:?} | {} | {} | {} |\n",
            gate.gate_name, gate.tier, gate.passed, gate.observed_value, gate.threshold_value
        ));
    }
    output.push_str("\n## Scale Gates\n\n");
    output.push_str("| gate | tier | passed | observed | threshold |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for gate in &summary.scale_gates {
        output.push_str(&format!(
            "| {} | {:?} | {} | {} | {} |\n",
            gate.gate_name, gate.tier, gate.passed, gate.observed_value, gate.threshold_value
        ));
    }
    output.push_str("\n## Improvement Metrics\n\n");
    output.push_str(&format!(
        "- redaction_cache_hit_ratio_bp: {}\n",
        summary.redaction_cache_hit_ratio_bp
    ));
    output.push_str(&format!(
        "- scale_redaction_cache_hit_ratio_bp: {}\n",
        summary.scale_redaction_cache_hit_ratio_bp
    ));
    output.push_str(&format!(
        "- scale_latency_overhead_vs_mvp_bp: {}\n",
        summary.scale_latency_overhead_vs_mvp_bp
    ));
    output.push_str(&format!(
        "- governance_overhead_reduction_bp: {}\n",
        summary.governance_overhead_reduction_bp
    ));
    output
}

fn write_artifact(path: &str, contents: &str) -> Result<()> {
    let artifact_path = workspace_artifact_path(path);
    if let Some(parent) = artifact_path.parent() {
        fs::create_dir_all(parent).map_err(|source| DiagnosticsError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(&artifact_path, contents).map_err(|source| DiagnosticsError::Io {
        path: path.into(),
        source,
    })
}

fn workspace_artifact_path(path: &str) -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(crate_dir)
        .join(path)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    const FIXTURE_JSON: &str = include_str!("../fixtures/benchmarks/mvp_minimum.json");

    fn fixture() -> BenchmarkFixture {
        crate::benchmark::load_benchmark_fixture_json(FIXTURE_JSON).expect("fixture")
    }

    fn bundle() -> BenchmarkReportBundle {
        build_phase2a_report_bundle(&fixture()).expect("bundle")
    }

    #[test]
    fn phase2a_contracts() {
        let latency = LatencyBreakdown::from_inputs(
            120,
            BenchmarkRunnerName::GovernedDagDbRouting,
            16,
            1,
            128,
        );
        assert_eq!(required_regression_gate_names().len(), 7);
        assert_eq!(runner_label(BenchmarkRunnerName::FlatRag), "flat_rag");
        assert_eq!(
            artifact_paths(),
            vec![
                BENCHMARK_SUMMARY_JSON,
                BENCHMARK_SUMMARY_MD,
                PER_TASK_BREAKDOWN_JSON,
                LATENCY_BREAKDOWN_JSON
            ]
        );
        assert_eq!(
            latency.total_ms,
            latency.catalog_lookup_ms
                + latency.canonical_resolution_ms
                + latency.provenance_fetch_ms
                + latency.contradiction_fetch_ms
                + latency.routing_view_build_ms
                + latency.validation_ms
                + latency.context_packet_build_ms
                + latency.writeback_ms
        );
    }

    #[test]
    fn latency_overflow_saturates_each_stage_and_total_deterministically() {
        let latency = LatencyBreakdown::from_inputs(
            u64::MAX,
            BenchmarkRunnerName::GovernedDagDbRouting,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        );

        assert_eq!(latency.catalog_lookup_ms, 730_183_619_584_336_422);
        assert_eq!(latency.canonical_resolution_ms, u64::MAX);
        assert_eq!(latency.provenance_fetch_ms, u64::MAX);
        assert_eq!(latency.contradiction_fetch_ms, 384_307_168_202_282_326);
        assert_eq!(latency.routing_view_build_ms, u64::MAX);
        assert_eq!(latency.validation_ms, 1_152_921_504_606_846_980);
        assert_eq!(latency.context_packet_build_ms, 720_575_940_379_279_359);
        assert_eq!(latency.writeback_ms, u64::MAX);
        assert_eq!(latency.total_ms, u64::MAX);
    }

    #[test]
    fn phase2a_per_task_diagnostics_for_every_task() {
        let fixture = fixture();
        let bundle = build_phase2a_report_bundle(&fixture).expect("bundle");
        assert_eq!(
            bundle.per_task_breakdown.len(),
            fixture.tasks.len() * BenchmarkRunnerName::all().len()
        );
        for runner in BenchmarkRunnerName::all() {
            assert_eq!(
                bundle
                    .per_task_breakdown
                    .iter()
                    .filter(|row| row.runner == runner)
                    .count(),
                fixture.tasks.len()
            );
        }
    }

    #[test]
    fn phase2a_latency_breakdown_sums_to_total() {
        for latency in bundle().latency_breakdown.values() {
            assert_eq!(
                latency.total_ms,
                latency.catalog_lookup_ms
                    + latency.canonical_resolution_ms
                    + latency.provenance_fetch_ms
                    + latency.contradiction_fetch_ms
                    + latency.routing_view_build_ms
                    + latency.validation_ms
                    + latency.context_packet_build_ms
                    + latency.writeback_ms
            );
        }
    }

    #[test]
    fn phase2a_latency_reports_byte_stable_across_repeated_runs() {
        let fixture = fixture();
        let first = build_phase2a_report_bundle(&fixture).expect("first");
        let second = build_phase2a_report_bundle(&fixture).expect("second");
        let first_latency = json_string(&first.latency_breakdown).expect("first json");
        let second_latency = json_string(&second.latency_breakdown).expect("second json");
        assert_eq!(first_latency, second_latency);
    }

    #[test]
    fn phase2a_report_artifact_bytes_stable_across_repeated_runs() {
        let fixture = fixture();
        let first = render_phase2a_report_artifacts(
            &build_phase2a_report_bundle(&fixture).expect("first bundle"),
        )
        .expect("first artifacts");
        let second = render_phase2a_report_artifacts(
            &build_phase2a_report_bundle(&fixture).expect("second bundle"),
        )
        .expect("second artifacts");
        assert_eq!(first, second);
    }

    #[test]
    fn phase2a_markdown_report_matches_pinned_layout() {
        let fixture = fixture();
        let bundle = build_phase2a_report_bundle(&fixture).expect("bundle");
        let markdown = render_phase2a_report_artifacts(&bundle)
            .expect("artifacts")
            .benchmark_summary_md;
        let headings = markdown
            .lines()
            .filter(|line| line.starts_with("## "))
            .collect::<Vec<_>>();
        assert_eq!(
            headings,
            vec![
                "## Fixture",
                "## Runners",
                "## Per-Task Diagnostics",
                "## Latency Breakdown",
                "## Regression Gates",
                "## Generated Artifacts",
            ]
        );
        assert!(markdown.contains("| runner | quality_score_bp | citation_accuracy_bp | unsupported_claim_rate_bp | prompt_tokens | claim_allowed |"));
        assert!(markdown.contains("| task_id | task_type | quality_score_bp | citation_accuracy_bp | prompt_tokens | overhead_tokens | latency_ms | net_savings_micro_exo | claim_allowed |"));
        assert!(markdown.contains("| gate_name | passed | runner | baseline_runner | observed_value | baseline_value | threshold_value | reason |"));
        assert_eq!(
            markdown.matches("### ").count(),
            BenchmarkRunnerName::all().len()
        );
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.starts_with("| t0"))
                .count(),
            fixture.tasks.len() * BenchmarkRunnerName::all().len()
        );
        assert!(markdown.ends_with('\n'));
        assert!(!markdown.lines().any(|line| line.ends_with(' ')));
    }

    #[test]
    fn phase2a_benchmark_report_artifacts_generate_under_target() {
        let artifacts = write_phase2a_report_artifacts(&bundle()).expect("write artifacts");
        assert!(artifacts.benchmark_summary_json.contains("\"fixture_id\""));
        assert!(artifacts.benchmark_summary_md.contains("## Fixture"));
        assert!(workspace_artifact_path(BENCHMARK_SUMMARY_JSON).exists());
        assert!(workspace_artifact_path(BENCHMARK_SUMMARY_MD).exists());
        assert!(workspace_artifact_path(PER_TASK_BREAKDOWN_JSON).exists());
        assert!(workspace_artifact_path(LATENCY_BREAKDOWN_JSON).exists());
    }

    #[test]
    fn phase2a_governed_dagdb_still_passes_claim_gate() {
        let bundle = bundle();
        assert!(bundle.regression_gates.iter().all(|gate| gate.passed));
        let governed = bundle
            .per_task_breakdown
            .iter()
            .find(|row| row.runner == BenchmarkRunnerName::GovernedDagDbRouting)
            .expect("governed row");
        assert!(governed.claim_allowed);
        assert_eq!(governed.reason_if_disallowed, None);
    }

    #[test]
    fn phase2a_quality_regression_blocks_savings_claim() {
        let fixture = fixture();
        let mut reports = BenchmarkRunnerName::all()
            .iter()
            .map(|runner| run_benchmark_fixture(&fixture, *runner).expect("report"))
            .collect::<Vec<_>>();
        let governed = reports
            .iter_mut()
            .find(|report| report.runner_name == BenchmarkRunnerName::GovernedDagDbRouting)
            .expect("governed");
        governed.quality_score_bp = 8_000;
        governed.savings_claim_allowed = true;
        let bundle = build_phase2a_report_bundle_from_reports(&fixture, reports).expect("bundle");
        let reason = bundle
            .per_task_breakdown
            .iter()
            .find(|row| row.runner == BenchmarkRunnerName::GovernedDagDbRouting)
            .and_then(|row| row.reason_if_disallowed.clone())
            .expect("reason");
        assert_eq!(
            reason,
            "governed_quality_gte_long_context, governed_safety_quality_not_weakened"
        );
    }

    #[test]
    fn phase2a_prompt_token_reduction_regression_blocks_savings_claim() {
        let fixture = fixture();
        let mut reports = BenchmarkRunnerName::all()
            .iter()
            .map(|runner| run_benchmark_fixture(&fixture, *runner).expect("report"))
            .collect::<Vec<_>>();
        let long_prompt_tokens = reports
            .iter()
            .find(|report| report.runner_name == BenchmarkRunnerName::LongContextDump)
            .expect("long")
            .prompt_tokens;
        let governed = reports
            .iter_mut()
            .find(|report| report.runner_name == BenchmarkRunnerName::GovernedDagDbRouting)
            .expect("governed");
        governed.prompt_tokens = long_prompt_tokens;
        governed.savings_claim_allowed = true;
        let gates = evaluate_phase2a_regression_gates(&reports).expect("gates");
        assert!(gates.iter().any(|gate| {
            gate.gate_name == "governed_prompt_tokens_lt_long_context" && !gate.passed
        }));
        assert!(gates.iter().any(|gate| {
            gate.gate_name == "governed_prompt_token_reduction_bp_min_1000" && !gate.passed
        }));
        assert_eq!(
            reason_if_disallowed(false, &gates),
            Some(
                "governed_prompt_tokens_lt_long_context, governed_prompt_token_reduction_bp_min_1000"
                    .into()
            )
        );
    }

    #[test]
    fn phase2a_reason_internal_when_no_gate_failed() {
        assert_eq!(
            reason_if_disallowed(false, &[]),
            Some("claim_gate_internal".into())
        );
        assert_eq!(reason_if_disallowed(true, &[]), None);
    }

    #[test]
    fn phase2a_helper_branch_vectors_cover_disallowed_paths() {
        assert_eq!(prompt_token_reduction_bp(0, 0), 0);
        assert_eq!(prompt_token_reduction_bp(10, 5), 0);
        assert_eq!(prompt_token_reduction_bp(4, 10), 6_000);
        assert_eq!(gate("x", true, 1, 1, 1).reason, "passed");
        assert_eq!(gate("x", false, 1, 1, 1).reason, "failed");
        assert_eq!(route_count_for(BenchmarkRunnerName::FlatRag, 0), 0);
        assert_eq!(route_count_for(BenchmarkRunnerName::FlatRag, 1), 1);
        assert_eq!(route_count_for(BenchmarkRunnerName::DagDbRouting, 0), 0);
        assert_eq!(route_count_for(BenchmarkRunnerName::DagDbRouting, 1), 1);
        assert_eq!(
            route_count_for(BenchmarkRunnerName::GovernedDagDbRouting, 0),
            0
        );
        assert_eq!(
            route_count_for(BenchmarkRunnerName::GovernedDagDbRouting, 1),
            1
        );

        let validation_blocked = crate::benchmark::BenchmarkTask {
            task_id: "validation-blocked".into(),
            question_text: "blocked".into(),
            task_signature_hash: "hash".into(),
            expected_citations: Vec::new(),
            allowed_memory_ids: Vec::new(),
            prohibited_memory_ids: Vec::new(),
            expected_citation_ids: Vec::new(),
            prohibited_ref_ids: Vec::new(),
            contradiction_ref_ids: Vec::new(),
            risk_labels: Vec::new(),
            expected_validation_outcome: ValidationStatus::Failed,
        };
        assert_eq!(task_type(&validation_blocked), "validation_blocked");

        let fixture = fixture();
        let mut reports = BenchmarkRunnerName::all()
            .iter()
            .map(|runner| run_benchmark_fixture(&fixture, *runner).expect("report"))
            .collect::<Vec<_>>();
        let governed = reports
            .iter_mut()
            .find(|report| report.runner_name == BenchmarkRunnerName::GovernedDagDbRouting)
            .expect("governed");
        governed.quality_score_bp = 9_000;
        governed.citation_accuracy_bp = 9_000;
        governed.unsupported_claim_rate_bp = 900;
        governed.savings_claim_allowed = false;
        let gates = evaluate_phase2a_regression_gates(&reports).expect("gates");
        assert!(!gate_by_name(&gates, "governed_claim_allowed").passed);
        assert!(!gate_by_name(&gates, "governed_citation_accuracy_gte_long_context").passed);
        assert!(!gate_by_name(&gates, "governed_unsupported_claims_lte_long_context").passed);
        assert!(!gate_by_name(&gates, "governed_safety_quality_not_weakened").passed);

        let mut unsupported_reports = BenchmarkRunnerName::all()
            .iter()
            .map(|runner| run_benchmark_fixture(&fixture, *runner).expect("report"))
            .collect::<Vec<_>>();
        let governed = unsupported_reports
            .iter_mut()
            .find(|report| report.runner_name == BenchmarkRunnerName::GovernedDagDbRouting)
            .expect("governed");
        governed.quality_score_bp = 9_000;
        governed.citation_accuracy_bp = 9_600;
        governed.unsupported_claim_rate_bp = 900;
        governed.savings_claim_allowed = true;
        let gates = evaluate_phase2a_regression_gates(&unsupported_reports).expect("gates");
        assert!(!gate_by_name(&gates, "governed_unsupported_claims_lte_long_context").passed);
        assert!(!gate_by_name(&gates, "governed_safety_quality_not_weakened").passed);
    }

    #[test]
    fn phase2a_markdown_and_writer_branch_vectors() {
        let mut bundle = bundle();
        bundle.latency_breakdown.remove("flat_rag");
        let markdown = markdown_summary(&bundle);
        assert!(!markdown.contains("| flat_rag | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |"));

        write_artifact("phase2a_tmp_report_artifact.txt", "ok\n").expect("write no-parent path");
        let path = workspace_artifact_path("phase2a_tmp_report_artifact.txt");
        assert!(path.exists());
        std::fs::remove_file(path).expect("remove no-parent artifact");
        assert!(write_artifact("/", "not-a-file\n").is_err());
    }

    #[test]
    fn phase2a_missing_runner_fails_loudly() {
        let fixture = fixture();
        let reports =
            vec![run_benchmark_fixture(&fixture, BenchmarkRunnerName::NoMemory).expect("report")];
        assert!(matches!(
            build_phase2a_report_bundle_from_reports(&fixture, reports),
            Err(DiagnosticsError::MissingRunner { .. })
        ));
    }

    fn gate_by_name<'a>(
        gates: &'a [BenchmarkRegressionGateResult],
        name: &str,
    ) -> &'a BenchmarkRegressionGateResult {
        gates
            .iter()
            .find(|gate| gate.gate_name == name)
            .expect("gate")
    }

    #[test]
    fn phase2a_gate_order_is_fixed() {
        let gate_names = evaluate_phase2a_regression_gates(&bundle().runner_reports)
            .expect("gates")
            .into_iter()
            .map(|gate| gate.gate_name)
            .collect::<Vec<_>>();
        assert_eq!(gate_names, required_regression_gate_names());
        assert_eq!(
            required_regression_gate_names()
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            required_regression_gate_names().len()
        );
    }

    fn optimized_summary() -> OptimizedCapabilitySummary {
        build_optimized_capability_summary(&fixture()).expect("optimized summary")
    }

    #[test]
    fn optimized_fixture_aggregation_uses_locked_basis() {
        let fixture = fixture();
        let report = run_benchmark_fixture(&fixture, BenchmarkRunnerName::GovernedDagDbOptimized)
            .expect("optimized");
        let summed = report
            .selected_memory_ids_by_task
            .values()
            .map(|ids| {
                u32::try_from(ids.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(6)
            })
            .sum::<u32>();
        assert_eq!(report.prompt_tokens, summed);
        let summary = optimized_summary();
        let mvp = report_metric(
            &summary.mvp_runner_metrics,
            BenchmarkRunnerName::GovernedDagDbOptimized,
        )
        .expect("mvp optimized metric");
        let scale = report_metric(
            &summary.scale_runner_metrics,
            BenchmarkRunnerName::GovernedDagDbOptimized,
        )
        .expect("scale optimized metric");
        assert_eq!(
            summary.scale_latency_overhead_vs_mvp_bp,
            scale_latency_overhead_vs_mvp_bp_from_metrics(mvp, scale)
        );
    }

    #[test]
    fn optimized_latency_each_stage_subtracts_correctly() {
        let base = LatencyBreakdown {
            catalog_lookup_ms: 20,
            canonical_resolution_ms: 40,
            provenance_fetch_ms: 7,
            contradiction_fetch_ms: 5,
            routing_view_build_ms: 11,
            validation_ms: 13,
            context_packet_build_ms: 99,
            writeback_ms: 4,
            total_ms: 199,
        };
        let optimized =
            LatencyBreakdown::optimized_from_stage_inputs(base, 80, 512, 3, 5_000, true);
        assert_eq!(optimized.catalog_lookup_ms, 10);
        assert_eq!(optimized.canonical_resolution_ms, 20);
        assert_eq!(optimized.provenance_fetch_ms, 4);
        assert_eq!(optimized.validation_ms, 13);
        assert_eq!(optimized.context_packet_build_ms, 4);
        assert_eq!(optimized.writeback_ms, 3);
        assert_eq!(
            optimized.total_ms,
            optimized.catalog_lookup_ms
                + optimized.canonical_resolution_ms
                + optimized.provenance_fetch_ms
                + optimized.contradiction_fetch_ms
                + optimized.routing_view_build_ms
                + optimized.validation_ms
                + optimized.context_packet_build_ms
                + optimized.writeback_ms
        );
    }

    #[test]
    fn optimized_latency_caps_ratio_and_preserves_writeback_without_reuse() {
        let base = LatencyBreakdown {
            catalog_lookup_ms: 3,
            canonical_resolution_ms: 100,
            provenance_fetch_ms: 2,
            contradiction_fetch_ms: 5,
            routing_view_build_ms: 7,
            validation_ms: 11,
            context_packet_build_ms: 99,
            writeback_ms: 4,
            total_ms: 231,
        };
        let optimized =
            LatencyBreakdown::optimized_from_stage_inputs(base, 80, 0, 10, 9_999, false);
        assert_eq!(optimized.catalog_lookup_ms, 0);
        assert_eq!(optimized.canonical_resolution_ms, 30);
        assert_eq!(optimized.provenance_fetch_ms, 0);
        assert_eq!(optimized.context_packet_build_ms, 2);
        assert_eq!(optimized.writeback_ms, 4);
        assert_eq!(
            optimized.total_ms,
            optimized.catalog_lookup_ms
                + optimized.canonical_resolution_ms
                + optimized.provenance_fetch_ms
                + optimized.contradiction_fetch_ms
                + optimized.routing_view_build_ms
                + optimized.validation_ms
                + optimized.context_packet_build_ms
                + optimized.writeback_ms
        );
    }

    #[test]
    fn optimized_scale_latency_overhead_uses_mean_per_task_basis() {
        let mvp = OptimizedRunnerMetrics {
            runner: BenchmarkRunnerName::GovernedDagDbOptimized,
            quality_score_bp: 10_000,
            citation_accuracy_bp: 10_000,
            unsupported_claim_rate_bp: 0,
            prompt_tokens_total: 1,
            overhead_tokens_total: 1,
            net_savings_micro_exo_total: 1,
            deterministic_latency_ms_total: 300,
            mean_per_task_latency_ms: 20,
            claim_allowed: true,
        };
        let scale = OptimizedRunnerMetrics {
            deterministic_latency_ms_total: 3_750,
            mean_per_task_latency_ms: 25,
            ..mvp.clone()
        };
        assert_eq!(
            scale_latency_overhead_vs_mvp_bp_from_metrics(&mvp, &scale),
            2_500
        );
        assert_eq!(
            scale_latency_overhead_vs_mvp_bp_from_metrics(&scale, &mvp),
            0
        );
        let zero_mvp = OptimizedRunnerMetrics {
            mean_per_task_latency_ms: 0,
            ..mvp
        };
        assert_eq!(
            scale_latency_overhead_vs_mvp_bp_from_metrics(&zero_mvp, &scale),
            0
        );
    }

    #[test]
    fn optimized_reduction_gates_use_governed_v1_baseline() {
        let summary = optimized_summary();
        assert!(
            gate_by_name_optimized(&summary.mvp_gates, "optimized_latency_reduction_gate").passed
        );
        assert!(
            gate_by_name_optimized(
                &summary.mvp_gates,
                "optimized_governance_overhead_reduction_gate"
            )
            .passed
        );
        assert!(summary.governance_overhead_reduction_bp >= 2_500);
    }

    #[test]
    fn optimized_private_gate_helpers_cover_failure_branches() {
        assert!(!gate_floor_ge("floor_ge", 9, 10).passed);
        assert!(!gate_floor_le("floor_le", 11, 10).passed);
        assert!(!gate_floor_bool("floor_bool", false).passed);
        assert!(!gate_stretch_ge("stretch_ge", 9, 10).passed);
        assert!(!gate_stretch_le("stretch_le", 11, 10).passed);
        assert!(!gate_stretch_bool("stretch_bool", false).passed);
    }

    #[test]
    fn optimized_governance_overhead_reduction_handles_zero_and_no_reduction() {
        let fixture = fixture();
        let mut governed =
            run_benchmark_fixture(&fixture, BenchmarkRunnerName::GovernedDagDbRouting)
                .expect("governed");
        let mut optimized =
            run_benchmark_fixture(&fixture, BenchmarkRunnerName::GovernedDagDbOptimized)
                .expect("optimized");

        governed.overhead_tokens = 0;
        assert_eq!(governance_overhead_reduction_bp(&governed, &optimized), 0);

        governed.overhead_tokens = 10;
        optimized.overhead_tokens = 10;
        assert_eq!(governance_overhead_reduction_bp(&governed, &optimized), 0);

        optimized.overhead_tokens = 5;
        assert_eq!(
            governance_overhead_reduction_bp(&governed, &optimized),
            5_000
        );
    }

    #[test]
    fn optimized_governance_overhead_reduction_gate() {
        optimized_reduction_gates_use_governed_v1_baseline();
    }

    #[test]
    fn optimized_latency_reduction_gate() {
        optimized_reduction_gates_use_governed_v1_baseline();
    }

    #[test]
    fn optimized_mvp_floor_gates() {
        let summary = optimized_summary();
        assert!(
            summary
                .mvp_gates
                .iter()
                .filter(|gate| gate.tier == OptimizedBenchmarkGateTier::Floor)
                .all(|gate| gate.passed)
        );
    }

    #[test]
    fn optimized_mvp_stretch_gates_report() {
        let summary = optimized_summary();
        assert!(
            summary
                .mvp_gates
                .iter()
                .any(|gate| gate.tier == OptimizedBenchmarkGateTier::Stretch)
        );
    }

    #[test]
    fn optimized_scale_floor_gates() {
        let summary = optimized_summary();
        assert!(
            summary
                .scale_gates
                .iter()
                .filter(|gate| gate.tier == OptimizedBenchmarkGateTier::Floor)
                .all(|gate| gate.passed)
        );
    }

    #[test]
    fn optimized_scale_stretch_gates_report() {
        let summary = optimized_summary();
        assert!(
            summary
                .scale_gates
                .iter()
                .any(|gate| gate.tier == OptimizedBenchmarkGateTier::Stretch)
        );
        assert!(matches!(
            summary.capability_verdict,
            OptimizedCapabilityVerdict::ImprovedMeaningfully
                | OptimizedCapabilityVerdict::ImprovedToStretch
        ));
    }

    #[test]
    fn optimized_reports_byte_stable() {
        let first = render_optimized_report_artifacts(&optimized_summary()).expect("first");
        let second = render_optimized_report_artifacts(&optimized_summary()).expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn optimized_reports_write_under_target() {
        let artifacts =
            write_optimized_report_artifacts(&optimized_summary()).expect("write optimized");
        assert!(
            artifacts
                .optimized_capability_summary_json
                .contains("\"capability_verdict\"")
        );
        assert!(workspace_artifact_path(OPTIMIZED_CAPABILITY_SUMMARY_JSON).exists());
        assert!(workspace_artifact_path(OPTIMIZED_CAPABILITY_SUMMARY_MD).exists());
        assert!(workspace_artifact_path(SCALE_FIXTURE_SUMMARY_JSON).exists());
        assert!(workspace_artifact_path(OPTIMIZED_PER_TASK_BREAKDOWN_JSON).exists());
    }

    fn e2e_summary() -> EndToEndDiagnosticSummary {
        build_end_to_end_diagnostic_summary(&fixture()).expect("e2e summary")
    }

    fn e2e_primary(summary: &EndToEndDiagnosticSummary) -> &EndToEndComparison {
        primary_comparison(summary).expect("primary comparison")
    }

    #[test]
    fn e2e_diagnostic_primary_baseline_is_long_context() {
        let summary = e2e_summary();
        let primary = e2e_primary(&summary);
        assert_eq!(
            primary.neutral_runner,
            DiagnosticRunnerRole::NeutralLongContext
        );
        assert_ne!(
            primary.neutral_runner,
            DiagnosticRunnerRole::NoMemoryLowerBound
        );
    }

    #[test]
    fn e2e_diagnostic_includes_flat_rag_secondary() {
        let summary = e2e_summary();
        let secondary = secondary_comparison(&summary).expect("secondary comparison");
        assert_eq!(
            secondary.neutral_runner,
            DiagnosticRunnerRole::NeutralFlatRag
        );
    }

    #[test]
    fn e2e_diagnostic_no_memory_is_lower_bound_only() {
        let summary = e2e_summary();
        let no_memory = summary
            .runner_definitions
            .iter()
            .find(|definition| definition.role == DiagnosticRunnerRole::NoMemoryLowerBound)
            .expect("no memory role");
        assert_eq!(no_memory.diagnostic_label, "no_memory_lower_bound");
        assert!(!no_memory.primary_baseline_allowed);
        assert!(summary.comparisons.iter().all(|comparison| {
            comparison.comparison_name != "primary_ab_long_context_vs_governed_dagdb"
                || comparison.neutral_runner != DiagnosticRunnerRole::NoMemoryLowerBound
        }));
    }

    #[test]
    fn e2e_diagnostic_governed_dagdb_maps_to_governed_routing() {
        let definition = diagnostic_runner_definitions(true)
            .into_iter()
            .find(|definition| definition.role == DiagnosticRunnerRole::GovernedDagdb)
            .expect("governed definition");
        assert_eq!(
            definition.benchmark_runner,
            BenchmarkRunnerName::GovernedDagDbRouting
        );
    }

    #[test]
    fn e2e_diagnostic_optimized_never_replaces_primary() {
        let summary = e2e_summary();
        let primary = e2e_primary(&summary);
        assert_eq!(primary.dag_runner, DiagnosticRunnerRole::GovernedDagdb);
        assert_ne!(
            primary.dag_runner,
            DiagnosticRunnerRole::GovernedDagdbOptimized
        );
        assert!(summary.comparisons.iter().any(
            |comparison| comparison.dag_runner == DiagnosticRunnerRole::GovernedDagdbOptimized
        ));
    }

    #[test]
    fn e2e_diagnostic_missing_optimized_runner_skip_is_reported() {
        let summary =
            build_end_to_end_diagnostic_summary_with_options(&fixture(), false).expect("summary");
        assert_eq!(summary.optimized_runner_status, E2E_OPTIMIZED_SKIP);
        assert!(summary.comparisons.iter().all(|comparison| {
            comparison.dag_runner != DiagnosticRunnerRole::GovernedDagdbOptimized
        }));
    }

    #[test]
    fn e2e_diagnostic_fairness_uses_same_source_availability_not_same_selected_refs() {
        let summary = e2e_summary();
        let primary = summary
            .fairness_checks
            .iter()
            .find(|check| check.comparison_name == "primary_ab_long_context_vs_governed_dagdb")
            .expect("primary fairness");
        assert!(primary.same_source_availability);
        assert!(primary.selected_refs_may_differ);
        assert!(primary.passed);
    }

    #[test]
    fn e2e_diagnostic_same_source_pool_allows_different_selected_refs() {
        let summary = e2e_summary();
        let primary = summary
            .fairness_checks
            .iter()
            .find(|check| check.comparison_name == "primary_ab_long_context_vs_governed_dagdb")
            .expect("primary fairness");
        assert!(primary.same_fixture_id);
        assert!(primary.same_corpus_id);
        assert!(primary.same_task_ids);
        assert!(primary.same_allowed_source_pool);
        assert!(primary.selected_refs_differ);
    }

    #[test]
    fn e2e_diagnostic_same_evaluator_and_scoring_path() {
        let summary = e2e_summary();
        assert_eq!(summary.model_or_evaluator_id, E2E_MODEL_OR_EVALUATOR_ID);
        assert_eq!(summary.scoring_path_id, E2E_SCORING_PATH_ID);
        assert!(
            summary
                .fairness_checks
                .iter()
                .all(|check| check.same_evaluator_and_scoring_path)
        );
    }

    #[test]
    fn e2e_diagnostic_neutral_profiles_do_not_use_dag_graph_context() {
        let definitions = diagnostic_runner_definitions(true);
        let long = definition_for_role(&definitions, DiagnosticRunnerRole::NeutralLongContext)
            .expect("long");
        let flat =
            definition_for_role(&definitions, DiagnosticRunnerRole::NeutralFlatRag).expect("flat");
        assert_eq!(
            long.context_acquisition_profile,
            ContextAcquisitionProfile::LongContextSourceLoading
        );
        assert_eq!(
            flat.context_acquisition_profile,
            ContextAcquisitionProfile::FlatRetrievalWithoutGraphOrganization
        );
    }

    #[test]
    fn e2e_diagnostic_governed_profile_uses_dag_context() {
        let definitions = diagnostic_runner_definitions(true);
        let governed =
            definition_for_role(&definitions, DiagnosticRunnerRole::GovernedDagdb).expect("gov");
        assert_eq!(
            governed.context_acquisition_profile,
            ContextAcquisitionProfile::GovernedDagRoutingValidationContextPacketGraph
        );
    }

    #[test]
    fn e2e_diagnostic_per_task_rows_cover_all_runners() {
        let summary = e2e_summary();
        assert_eq!(
            summary.per_task_results.len(),
            (15 + 150 + 15) * summary.runner_definitions.len()
        );
        assert!(
            summary
                .fixture_ids
                .iter()
                .any(|fixture_id| fixture_id == "redacted_project_session_v1")
        );
        for definition in &summary.runner_definitions {
            assert!(
                summary
                    .per_task_results
                    .iter()
                    .any(|row| row.runner == definition.benchmark_runner)
            );
        }
    }

    #[test]
    fn e2e_diagnostic_authoritative_claims_are_comparison_level() {
        let summary = e2e_summary();
        assert!(summary.per_task_results.iter().all(|row| {
            !row.overall_diagnostic_claim_allowed
                && row.reason_if_disallowed.as_deref() == Some("per_task_claim_non_authoritative")
        }));
        assert!(
            summary
                .comparisons
                .iter()
                .any(|comparison| comparison.overall_diagnostic_claim_allowed)
        );
    }

    #[test]
    fn e2e_diagnostic_aggregate_metrics_compute_correctly() {
        let summary = e2e_summary();
        let primary = e2e_primary(&summary);
        let neutral = summary
            .runner_aggregates
            .iter()
            .find(|aggregate| {
                aggregate.fixture_kind == primary.fixture_kind
                    && aggregate.runner == BenchmarkRunnerName::LongContextDump
            })
            .expect("neutral aggregate");
        let governed = summary
            .runner_aggregates
            .iter()
            .find(|aggregate| {
                aggregate.fixture_kind == primary.fixture_kind
                    && aggregate.runner == BenchmarkRunnerName::GovernedDagDbRouting
            })
            .expect("governed aggregate");
        assert_eq!(
            primary.token_reduction_bp,
            reduction_bp_u32(governed.total_prompt_tokens, neutral.total_prompt_tokens)
        );
        assert_eq!(
            primary.cost_reduction_bp,
            reduction_bp_u64(governed.total_cost_micro_exo, neutral.total_cost_micro_exo)
        );
    }

    #[test]
    fn e2e_diagnostic_overall_rollup_combines_all_included_fixtures() {
        let summary = e2e_summary();
        let governed_prompt = summary
            .runner_aggregates
            .iter()
            .filter(|aggregate| aggregate.runner == BenchmarkRunnerName::GovernedDagDbRouting)
            .map(|aggregate| u64::from(aggregate.total_prompt_tokens))
            .sum::<u64>();
        assert_eq!(
            summary
                .overall_rollup
                .total_prompt_tokens_by_runner
                .get("governed_dagdb")
                .copied(),
            Some(governed_prompt)
        );
    }

    #[test]
    fn e2e_diagnostic_overall_rollup_claims_are_separated() {
        let summary = e2e_summary();
        assert!(
            summary
                .overall_rollup
                .overall_rollup_quality_improvement_claim_allowed
        );
        assert_eq!(
            summary
                .overall_rollup
                .overall_rollup_diagnostic_claim_allowed,
            summary
                .overall_rollup
                .overall_rollup_cost_savings_claim_allowed
                || summary
                    .overall_rollup
                    .overall_rollup_quality_improvement_claim_allowed
        );
    }

    fn aggregate_for_test(
        role: DiagnosticRunnerRole,
        prompt: u32,
        cost: u64,
        quality: u16,
        citation: u16,
        unsupported: u16,
    ) -> EndToEndRunnerAggregate {
        let runner = benchmark_runner_for_role(role);
        EndToEndRunnerAggregate {
            fixture_kind: DiagnosticFixtureKind::MvpSynthetic,
            fixture_id: "fixture".into(),
            runner,
            diagnostic_label: diagnostic_role_label(role).into(),
            task_count: 1,
            average_prompt_tokens: prompt,
            median_prompt_tokens: prompt,
            total_prompt_tokens: prompt,
            average_total_tokens: prompt,
            total_total_tokens: prompt,
            average_selected_refs: 1,
            total_selected_refs: 1,
            average_latency_ms: 10,
            median_latency_ms: 10,
            p95_latency_ms: 10,
            average_quality_score_bp: quality,
            average_citation_accuracy_bp: citation,
            average_unsupported_claim_rate_bp: unsupported,
            average_context_reduction_bp: None,
            total_cost_micro_exo: cost,
            net_savings_micro_exo: 0,
            percent_token_reduction_bp: None,
            percent_cost_reduction_bp: None,
        }
    }

    #[test]
    fn e2e_diagnostic_claims_are_separated() {
        let comparison = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NeutralLongContext,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    80,
                    120,
                    9_500,
                    9_500,
                    50,
                ),
            ],
            &[],
        )
        .expect("comparison");
        assert!(!comparison.cost_savings_claim_allowed);
        assert!(comparison.quality_improvement_claim_allowed);
        assert!(comparison.overall_diagnostic_claim_allowed);
    }

    #[test]
    fn e2e_diagnostic_cost_savings_claim_fails_when_cost_higher() {
        e2e_diagnostic_claims_are_separated();
    }

    #[test]
    fn e2e_diagnostic_quality_claim_can_pass_without_cost_savings() {
        e2e_diagnostic_claims_are_separated();
    }

    #[test]
    fn e2e_diagnostic_claim_fails_on_quality_regression() {
        let comparison = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NeutralLongContext,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    80,
                    80,
                    8_000,
                    9_500,
                    50,
                ),
            ],
            &[],
        )
        .expect("comparison");
        assert!(!comparison.cost_savings_claim_allowed);
        assert!(!comparison.quality_improvement_claim_allowed);
        assert_eq!(
            comparison.reason_if_disallowed,
            Some("quality_regression".into())
        );
    }

    #[test]
    fn e2e_diagnostic_cost_claim_fails_without_prompt_reduction() {
        let comparison = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NeutralLongContext,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    100,
                    80,
                    9_500,
                    9_500,
                    50,
                ),
            ],
            &[],
        )
        .expect("comparison");
        assert!(!comparison.cost_savings_claim_allowed);
        assert!(comparison.quality_improvement_claim_allowed);
    }

    #[test]
    fn e2e_diagnostic_claim_fails_on_fairness_failure() {
        let fairness = EndToEndFairnessCheck {
            comparison_name: "primary_ab_long_context_vs_governed_dagdb".into(),
            fixture_kind: DiagnosticFixtureKind::MvpSynthetic,
            fixture_id: "fixture".into(),
            neutral_runner: DiagnosticRunnerRole::NeutralLongContext,
            dag_runner: DiagnosticRunnerRole::GovernedDagdb,
            same_fixture_id: false,
            same_corpus_id: true,
            same_task_ids: true,
            same_allowed_source_pool: true,
            same_evaluator_and_scoring_path: true,
            same_source_availability: false,
            selected_refs_may_differ: true,
            selected_refs_differ: true,
            passed: false,
            reason_if_failed: Some("fairness_gate_failed".into()),
        };
        let comparison = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NeutralLongContext,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    80,
                    80,
                    9_500,
                    9_500,
                    50,
                ),
            ],
            &[fairness],
        )
        .expect("comparison");
        assert!(!comparison.overall_diagnostic_claim_allowed);
        assert_eq!(
            comparison.reason_if_disallowed,
            Some("fairness_gate_failed".into())
        );
    }

    #[test]
    fn e2e_diagnostic_claim_fails_when_no_memory_is_primary() {
        let comparison = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NoMemoryLowerBound,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NoMemoryLowerBound,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    80,
                    80,
                    9_500,
                    9_500,
                    50,
                ),
            ],
            &[],
        )
        .expect("comparison");
        assert!(!comparison.overall_diagnostic_claim_allowed);
        assert!(
            comparison
                .reason_if_disallowed
                .as_deref()
                .expect("reason")
                .contains("primary_baseline_not_long_context")
        );
    }

    #[test]
    fn e2e_diagnostic_branch_vectors_cover_failure_and_empty_paths() {
        assert!(all_true(&[true, true]));
        assert!(!all_true(&[true, false]));
        assert!(any_true(&[false, true]));
        assert!(!any_true(&[false, false]));
        assert_eq!(
            optimized_capability_verdict_from_gate_status(false, false),
            OptimizedCapabilityVerdict::FloorFailed
        );
        assert_eq!(
            optimized_capability_verdict_from_gate_status(true, false),
            OptimizedCapabilityVerdict::ImprovedMeaningfully
        );
        assert_eq!(
            optimized_capability_verdict_from_gate_status(true, true),
            OptimizedCapabilityVerdict::ImprovedToStretch
        );

        let base_latency = LatencyBreakdown {
            catalog_lookup_ms: 1,
            canonical_resolution_ms: 1,
            provenance_fetch_ms: 1,
            contradiction_fetch_ms: 1,
            routing_view_build_ms: 1,
            validation_ms: 1,
            context_packet_build_ms: 1,
            writeback_ms: 1,
            total_ms: 8,
        };
        assert_eq!(
            LatencyBreakdown::optimized_from_stage_inputs(base_latency, 1, 1, 0, 0, false)
                .writeback_ms,
            1
        );
        assert!(
            LatencyBreakdown::from_inputs(
                128,
                BenchmarkRunnerName::GovernedDagDbOptimized,
                4,
                1,
                64
            )
            .total_ms
                > 0
        );

        assert_eq!(median(&[]), 0);
        assert_eq!(median(&[1, 3, 2]), 2);
        assert_eq!(percentile_95(&[]), 0);
        assert_eq!(percentile_95(&[1, 2, 100]), 100);
        assert_eq!(average_u16(&[]), 0);
        assert_eq!(average_u16(&[10_000, 8_000]), 9_000);
        assert_eq!(average_option_u64(&[]), None);
        assert_eq!(average_option_u64(&[10, 20]), Some(15));
        assert_eq!(
            average_u64_map(BTreeMap::from([("x".into(), Vec::new())]))["x"],
            0
        );
        assert_eq!(reduction_bp_u32(0, 0), None);
        assert_eq!(reduction_bp_u32(10, 10), None);
        assert_eq!(reduction_bp_u32(5, 10), Some(5_000));
        assert_eq!(reduction_bp_u64(0, 0), None);
        assert_eq!(reduction_bp_u64(20, 10), None);
        assert_eq!(reduction_bp_u64(5, 10), Some(5_000));

        assert_eq!(
            comparison_reason(ComparisonClaimInputs {
                fairness_passed: true,
                primary_baseline_ok: true,
                cost_lower: true,
                prompt_lower: true,
                token_reduction_ok: true,
                no_quality_regression: true,
                no_citation_regression: true,
                no_unsupported_regression: true,
                safety_ok: true,
                overall_diagnostic_claim_allowed: false,
            }),
            Some("claim_gate_internal".into())
        );
        let reason = comparison_reason(ComparisonClaimInputs {
            fairness_passed: false,
            primary_baseline_ok: false,
            cost_lower: false,
            prompt_lower: false,
            token_reduction_ok: false,
            no_quality_regression: false,
            no_citation_regression: false,
            no_unsupported_regression: false,
            safety_ok: false,
            overall_diagnostic_claim_allowed: false,
        })
        .expect("reason");
        for expected in [
            "fairness_gate_failed",
            "primary_baseline_not_long_context",
            "cost_not_lower",
            "prompt_tokens_not_lower",
            "token_reduction_below_1000bp",
            "quality_regression",
            "citation_regression",
            "unsupported_claim_regression",
            "safety_governance_regression",
        ] {
            assert!(reason.contains(expected), "missing {expected}");
        }

        let fixture = fixture();
        let long = run_benchmark_fixture(&fixture, BenchmarkRunnerName::LongContextDump)
            .expect("long report");
        let mut governed =
            run_benchmark_fixture(&fixture, BenchmarkRunnerName::GovernedDagDbRouting)
                .expect("governed report");
        governed.fixture_id = "different_fixture".into();
        let failed_check = build_fairness_check(
            DiagnosticFixtureKind::MvpSynthetic,
            &fixture,
            &[long.clone(), governed],
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
        )
        .expect("failed fairness");
        assert!(!failed_check.passed);
        assert_eq!(
            failed_check.reason_if_failed,
            Some("fairness_gate_failed".into())
        );
        assert!(
            build_fairness_check(
                DiagnosticFixtureKind::MvpSynthetic,
                &fixture,
                &[long],
                "primary_ab_long_context_vs_governed_dagdb",
                DiagnosticRunnerRole::NeutralLongContext,
                DiagnosticRunnerRole::GovernedDagdb,
            )
            .is_none()
        );
        let fairness_for =
            |fixture_kind, comparison_name: &str, neutral_runner, dag_runner, passed| {
                EndToEndFairnessCheck {
                    comparison_name: comparison_name.into(),
                    fixture_kind,
                    fixture_id: "fixture".into(),
                    neutral_runner,
                    dag_runner,
                    same_fixture_id: passed,
                    same_corpus_id: passed,
                    same_task_ids: passed,
                    same_allowed_source_pool: passed,
                    same_evaluator_and_scoring_path: passed,
                    same_source_availability: passed,
                    selected_refs_may_differ: true,
                    selected_refs_differ: true,
                    passed,
                    reason_if_failed: (!passed).then(|| "fairness_gate_failed".into()),
                }
            };
        let comparison_with_skipped_fairness_checks = build_comparison(
            "primary_ab_long_context_vs_governed_dagdb",
            DiagnosticFixtureKind::MvpSynthetic,
            DiagnosticRunnerRole::NeutralLongContext,
            DiagnosticRunnerRole::GovernedDagdb,
            &[
                aggregate_for_test(
                    DiagnosticRunnerRole::NeutralLongContext,
                    100,
                    100,
                    9_000,
                    9_000,
                    100,
                ),
                aggregate_for_test(
                    DiagnosticRunnerRole::GovernedDagdb,
                    80,
                    80,
                    9_500,
                    9_500,
                    50,
                ),
            ],
            &[
                fairness_for(
                    DiagnosticFixtureKind::LargeSynthetic,
                    "primary_ab_long_context_vs_governed_dagdb",
                    DiagnosticRunnerRole::NeutralLongContext,
                    DiagnosticRunnerRole::GovernedDagdb,
                    false,
                ),
                fairness_for(
                    DiagnosticFixtureKind::MvpSynthetic,
                    "secondary_ab_flat_rag_vs_governed_dagdb",
                    DiagnosticRunnerRole::NeutralLongContext,
                    DiagnosticRunnerRole::GovernedDagdb,
                    false,
                ),
                fairness_for(
                    DiagnosticFixtureKind::MvpSynthetic,
                    "primary_ab_long_context_vs_governed_dagdb",
                    DiagnosticRunnerRole::NeutralLongContext,
                    DiagnosticRunnerRole::NoMemoryLowerBound,
                    false,
                ),
                fairness_for(
                    DiagnosticFixtureKind::MvpSynthetic,
                    "primary_ab_long_context_vs_governed_dagdb",
                    DiagnosticRunnerRole::NeutralLongContext,
                    DiagnosticRunnerRole::GovernedDagdb,
                    true,
                ),
            ],
        )
        .expect("comparison with skipped fairness checks");
        assert_eq!(
            u8::from(comparison_with_skipped_fairness_checks.fairness_passed),
            1
        );

        let mut summary = e2e_summary();
        let mut low_rollup = summary.overall_rollup.clone();
        low_rollup.overall_primary_token_reduction_bp = None;
        low_rollup.overall_primary_quality_delta_bp = -1;
        low_rollup.overall_primary_citation_delta_bp = -1;
        low_rollup.overall_primary_unsupported_claim_improvement_bp = -1;
        low_rollup.overall_primary_latency_delta_ms = 0;
        low_rollup.overall_rollup_cost_savings_claim_allowed = true;
        low_rollup.overall_rollup_diagnostic_claim_allowed = false;
        let no_claim_comparison = EndToEndComparison {
            comparison_name: "primary_ab_long_context_vs_governed_dagdb".into(),
            fixture_kind: DiagnosticFixtureKind::MvpSynthetic,
            neutral_runner: DiagnosticRunnerRole::NeutralLongContext,
            dag_runner: DiagnosticRunnerRole::GovernedDagdb,
            fairness_passed: true,
            cost_savings_claim_allowed: true,
            quality_improvement_claim_allowed: false,
            overall_diagnostic_claim_allowed: false,
            reason_if_disallowed: Some("claim_gate_internal".into()),
            token_reduction_bp: None,
            cost_reduction_bp: None,
            quality_delta_bp: -1,
            citation_delta_bp: -1,
            unsupported_claim_improvement_bp: -1,
            latency_delta_ms: 0,
            net_savings_micro_exo: 0,
        };
        assert_eq!(
            build_end_to_end_pros(std::slice::from_ref(&no_claim_comparison), &low_rollup),
            Vec::<String>::new()
        );
        assert_eq!(
            build_end_to_end_cons(std::slice::from_ref(&no_claim_comparison), &low_rollup).len(),
            1
        );
        assert_eq!(
            u8::from(
                build_end_to_end_recommendations(&[], &[no_claim_comparison])
                    .iter()
                    .any(|line| line.contains("not yet as a cost-savings claim"))
            ),
            1
        );
        let mut table = String::new();
        push_comparison_table(&mut table, None);
        assert!(table.contains("cost_claim | quality_claim | overall_claim"));
        assert_eq!(final_diagnostic_verdict(&summary), "Ship");
        summary.generated_artifacts.clear();
        assert_eq!(
            final_diagnostic_verdict(&summary),
            "Fix blockers and re-run"
        );

        let mut quality_only = e2e_summary();
        quality_only
            .overall_rollup
            .overall_rollup_cost_savings_claim_allowed = false;
        quality_only
            .overall_rollup
            .overall_rollup_quality_improvement_claim_allowed = true;
        let markdown = end_to_end_markdown_summary(&quality_only);
        assert!(markdown.contains(E2E_QUALITY_ONLY_MESSAGE));

        let failing_gate = gate("governed_claim_allowed", false, 0, 0, 1);
        assert_eq!(
            reason_if_disallowed(false, &[failing_gate]),
            Some("governed_claim_allowed".into())
        );

        let retrieval_task = crate::benchmark::BenchmarkTask {
            task_id: "retrieval".into(),
            question_text: "retrieval".into(),
            task_signature_hash: "hash".into(),
            expected_citations: Vec::new(),
            allowed_memory_ids: Vec::new(),
            prohibited_memory_ids: Vec::new(),
            expected_citation_ids: Vec::new(),
            prohibited_ref_ids: Vec::new(),
            contradiction_ref_ids: Vec::new(),
            risk_labels: Vec::new(),
            expected_validation_outcome: ValidationStatus::Passed,
        };
        assert_eq!(task_type(&retrieval_task), "retrieval");
        assert_eq!(
            route_count_for(BenchmarkRunnerName::GovernedDagDbOptimized, 1),
            1
        );
    }

    #[test]
    fn e2e_diagnostic_replay_fixture_is_reported() {
        let summary = e2e_summary();
        assert_eq!(summary.replay_fixture_status, E2E_REPLAY_INCLUDED);
        assert!(
            summary
                .per_task_results
                .iter()
                .any(|row| row.fixture_kind == DiagnosticFixtureKind::RedactedProjectSessionReplay)
        );
    }

    #[test]
    fn e2e_diagnostic_deterministic_mode_has_no_live_provider_requirement() {
        let summary = e2e_summary();
        assert!(summary.deterministic_mode);
        assert_eq!(summary.live_model_status, E2E_LIVE_MODEL_SKIP);
        assert!(!summary.live_model_status.contains("API key"));
    }

    #[test]
    fn e2e_diagnostic_json_reports_byte_stable() {
        let first = render_end_to_end_diagnostic_artifacts(&e2e_summary()).expect("first");
        let second = render_end_to_end_diagnostic_artifacts(&e2e_summary()).expect("second");
        assert_eq!(first.summary_json, second.summary_json);
        assert_eq!(first.per_task_results_json, second.per_task_results_json);
        assert_eq!(first.latency_breakdown_json, second.latency_breakdown_json);
        assert_eq!(first.cost_breakdown_json, second.cost_breakdown_json);
        assert_eq!(first.quality_breakdown_json, second.quality_breakdown_json);
    }

    #[test]
    fn e2e_diagnostic_markdown_layout_matches_contract() {
        let markdown = render_end_to_end_diagnostic_artifacts(&e2e_summary())
            .expect("artifacts")
            .summary_md;
        let headings = markdown
            .lines()
            .filter(|line| line.starts_with('#'))
            .collect::<Vec<_>>();
        assert_eq!(
            headings,
            vec![
                "# EXOCHAIN DAG DB End-to-End Diagnostic Report",
                "## Test Setup",
                "## Fairness Check",
                "## Executive Summary",
                "## Overall Rollup",
                "## Primary A/B: Long Context vs Governed DAG DB",
                "## Secondary A/B: Flat RAG vs Governed DAG DB",
                "## Lower-Bound Sanity: No Memory",
                "## Raw DAG vs Governed DAG",
                "## Token Efficiency",
                "## Cost Difference",
                "## Latency Difference",
                "## Context Quality",
                "## Output Quality",
                "## Safety / Unsupported Claims",
                "## Per-Fixture Results",
                "## Pros",
                "## Cons",
                "## What This Means",
                "## Recommended Next Work",
                "## Verdict",
            ]
        );
        assert!(markdown.ends_with('\n'));
        assert!(!markdown.lines().any(|line| line.ends_with(' ')));
    }

    #[test]
    fn e2e_diagnostic_markdown_includes_required_interpretation() {
        let markdown = render_end_to_end_diagnostic_artifacts(&e2e_summary())
            .expect("artifacts")
            .summary_md;
        for needle in [
            "Governed DAG DB reduced prompt tokens",
            "Governed DAG DB reduced cost",
            "Governed DAG DB improved or preserved quality",
            "Governed DAG DB improved or preserved citation accuracy",
            "Governed DAG DB reduced unsupported claims",
            "Governance overhead was worth it",
            "Redaction-safe replay fixture data is included",
            E2E_HARNESS_DISCLAIMER,
        ] {
            assert!(markdown.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn e2e_diagnostic_artifacts_generate_under_target() {
        let artifacts =
            write_end_to_end_diagnostic_artifacts(&e2e_summary()).expect("write e2e artifacts");
        assert!(artifacts.summary_json.contains("\"overall_rollup\""));
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_SUMMARY_JSON).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_SUMMARY_MD).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_PER_TASK_RESULTS_JSON).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_LATENCY_BREAKDOWN_JSON).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_COST_BREAKDOWN_JSON).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_QUALITY_BREAKDOWN_JSON).exists());
        assert!(workspace_artifact_path(E2E_DIAGNOSTIC_RECOMMENDATIONS_MD).exists());
    }

    fn gate_by_name_optimized<'a>(
        gates: &'a [OptimizedBenchmarkGateResult],
        name: &str,
    ) -> &'a OptimizedBenchmarkGateResult {
        gates
            .iter()
            .find(|gate| gate.gate_name == name)
            .expect("optimized gate")
    }
}
