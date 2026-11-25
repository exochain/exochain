//! Deterministic benchmark database silo isolation contracts.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use exo_core::Hash256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const MAIN_DATABASE_URL_ENV: &str = "EXO_DAGDB_MAIN_DATABASE_URL";
pub const NEUTRAL_BENCH_DATABASE_URL_ENV: &str = "EXO_DAGDB_NEUTRAL_BENCH_DATABASE_URL";
pub const CONTROL_BENCH_DATABASE_URL_ALIAS_ENV: &str = "EXO_DAGDB_CONTROL_BENCH_DATABASE_URL";
pub const GOVERNED_BENCH_DATABASE_URL_ENV: &str = "EXO_DAGDB_GOVERNED_BENCH_DATABASE_URL";

pub const BENCHMARK_ISOLATION_DIR: &str = "target/dagdb/benchmark_isolation";
pub const SILO_CONFIG_SUMMARY_JSON: &str =
    "target/dagdb/benchmark_isolation/silo_config_summary.json";
pub const SILO_VALIDATION_REPORT_JSON: &str =
    "target/dagdb/benchmark_isolation/silo_validation_report.json";
pub const SILO_CONTAMINATION_REPORT_JSON: &str =
    "target/dagdb/benchmark_isolation/silo_contamination_report.json";
pub const RUNNER_SILO_ASSIGNMENT_JSON: &str =
    "target/dagdb/benchmark_isolation/runner_silo_assignment.json";
pub const BENCHMARK_ISOLATION_SUMMARY_MD: &str =
    "target/dagdb/benchmark_isolation/benchmark_isolation_summary.md";

const E2E_DIAGNOSTIC_DIR: &str = "target/dagdb/end_to_end_diagnostics";
pub const SUMMARY_JSON: &str = "summary.json";
pub const PER_TASK_RESULTS_JSON: &str = "per_task_results.json";
pub const COST_BREAKDOWN_JSON: &str = "cost_breakdown.json";
pub const QUALITY_BREAKDOWN_JSON: &str = "quality_breakdown.json";
pub const LATENCY_BREAKDOWN_JSON: &str = "latency_breakdown.json";
pub const RECOMMENDATIONS_MD: &str = "recommendations.md";
const REPORT_SCHEMA_VERSION: &str = "dagdb_benchmark_isolation_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseSiloRole {
    Main,
    NeutralBenchmark,
    GovernedBenchmark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseSiloPurpose {
    ProductionMemory,
    NeutralBaseline,
    GovernedDagBenchmark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseSiloConfig {
    pub role: DatabaseSiloRole,
    pub purpose: DatabaseSiloPurpose,
    #[serde(skip_serializing)]
    pub database_url_env: String,
    pub configured: bool,
    pub tenant_id: String,
    pub namespace: String,
    pub read_only: bool,
    pub allow_benchmark_writes: bool,
    pub allow_synthetic_data: bool,
    pub allow_graph_routing: bool,
    pub allow_route_memory: bool,
    pub allow_canonical_graph: bool,
    pub allow_context_packet_graph: bool,
    pub allow_private_payload_reads: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkRunMode {
    NeutralLongContext,
    NeutralFlatRag,
    NoMemoryLowerBound,
    RawDagRouting,
    GovernedDagdb,
    GovernedDagdbOptimized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSiloAssignment {
    pub run_mode: BenchmarkRunMode,
    pub required_silo_role: DatabaseSiloRole,
    pub graph_routing_allowed: bool,
    pub writeback_allowed: bool,
    pub synthetic_data_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkIsolationValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub main_db_protected: bool,
    pub neutral_governed_separated: bool,
    pub runner_silo_assignments: Vec<BenchmarkSiloAssignment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiloContaminationStatus {
    Clean,
    Contaminated,
    UnknownNotObservable,
    NotConfiguredDemoMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiloContaminationCheck {
    pub checked_at_commit_or_run_id: String,
    pub main_db_used_for_benchmark: SiloContaminationStatus,
    pub neutral_used_graph_routing: SiloContaminationStatus,
    pub governed_used_neutral_state: SiloContaminationStatus,
    pub cross_silo_route_memory_reuse: SiloContaminationStatus,
    pub cross_silo_context_packet_reuse: SiloContaminationStatus,
    pub cross_silo_receipt_reuse: SiloContaminationStatus,
    pub contamination_detected: bool,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHashStatus {
    pub path: String,
    pub status: String,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkIsolationReport {
    pub schema_version: String,
    pub report_id: String,
    pub fixture_id: String,
    pub neutral_silo_status: DatabaseSiloConfig,
    pub governed_silo_status: DatabaseSiloConfig,
    pub main_silo_status: DatabaseSiloConfig,
    pub validation: BenchmarkIsolationValidation,
    pub contamination_check: SiloContaminationCheck,
    pub diagnostic_report_ids: Vec<String>,
    pub generated_at_harness_run_id: String,
    pub diagnostic_summary_hash: ArtifactHashStatus,
    pub per_task_results_hash: ArtifactHashStatus,
    pub cost_breakdown_hash: ArtifactHashStatus,
    pub quality_breakdown_hash: ArtifactHashStatus,
    pub latency_breakdown_hash: ArtifactHashStatus,
    pub recommendations_hash: ArtifactHashStatus,
    pub source_artifact_paths: Vec<String>,
    pub source_commit_or_run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContaminationEvidence {
    pub demo_mode: bool,
    pub main_db_used_for_benchmark: Option<bool>,
    pub neutral_used_graph_routing: Option<bool>,
    pub governed_used_neutral_state: Option<bool>,
    pub cross_silo_route_memory_reuse: Option<bool>,
    pub cross_silo_context_packet_reuse: Option<bool>,
    pub cross_silo_receipt_reuse: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkIsolationArtifacts {
    pub silo_config_summary_json: String,
    pub silo_validation_report_json: String,
    pub silo_contamination_report_json: String,
    pub runner_silo_assignment_json: String,
    pub benchmark_isolation_summary_md: String,
}

#[derive(Debug, Error)]
pub enum BenchmarkIsolationError {
    #[error("benchmark_silo_assignment_invalid: {reason}")]
    InvalidAssignment { reason: String },
    #[error("benchmark_isolation_io_failed: {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("benchmark_isolation_json_failed")]
    Json {
        #[source]
        source: serde_json::Error,
    },
}

#[must_use]
pub fn all_benchmark_run_modes() -> Vec<BenchmarkRunMode> {
    vec![
        BenchmarkRunMode::NeutralLongContext,
        BenchmarkRunMode::NeutralFlatRag,
        BenchmarkRunMode::NoMemoryLowerBound,
        BenchmarkRunMode::RawDagRouting,
        BenchmarkRunMode::GovernedDagdb,
        BenchmarkRunMode::GovernedDagdbOptimized,
    ]
}

#[must_use]
pub fn default_silo_configs_from_env<F>(env_lookup: F) -> Vec<DatabaseSiloConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let neutral_env = if env_lookup(NEUTRAL_BENCH_DATABASE_URL_ENV).is_some() {
        NEUTRAL_BENCH_DATABASE_URL_ENV
    } else {
        CONTROL_BENCH_DATABASE_URL_ALIAS_ENV
    };
    vec![
        DatabaseSiloConfig {
            role: DatabaseSiloRole::Main,
            purpose: DatabaseSiloPurpose::ProductionMemory,
            database_url_env: MAIN_DATABASE_URL_ENV.into(),
            configured: env_lookup(MAIN_DATABASE_URL_ENV).is_some(),
            tenant_id: "main".into(),
            namespace: "production".into(),
            read_only: true,
            allow_benchmark_writes: false,
            allow_synthetic_data: false,
            allow_graph_routing: true,
            allow_route_memory: true,
            allow_canonical_graph: true,
            allow_context_packet_graph: true,
            allow_private_payload_reads: false,
        },
        DatabaseSiloConfig {
            role: DatabaseSiloRole::NeutralBenchmark,
            purpose: DatabaseSiloPurpose::NeutralBaseline,
            database_url_env: neutral_env.into(),
            configured: env_lookup(neutral_env).is_some(),
            tenant_id: "benchmark_neutral".into(),
            namespace: "neutral_benchmark".into(),
            read_only: false,
            allow_benchmark_writes: true,
            allow_synthetic_data: true,
            allow_graph_routing: false,
            allow_route_memory: false,
            allow_canonical_graph: false,
            allow_context_packet_graph: false,
            allow_private_payload_reads: false,
        },
        DatabaseSiloConfig {
            role: DatabaseSiloRole::GovernedBenchmark,
            purpose: DatabaseSiloPurpose::GovernedDagBenchmark,
            database_url_env: GOVERNED_BENCH_DATABASE_URL_ENV.into(),
            configured: env_lookup(GOVERNED_BENCH_DATABASE_URL_ENV).is_some(),
            tenant_id: "benchmark_governed".into(),
            namespace: "governed_benchmark".into(),
            read_only: false,
            allow_benchmark_writes: true,
            allow_synthetic_data: true,
            allow_graph_routing: true,
            allow_route_memory: true,
            allow_canonical_graph: true,
            allow_context_packet_graph: true,
            allow_private_payload_reads: false,
        },
    ]
}

#[must_use]
pub fn default_silo_configs() -> Vec<DatabaseSiloConfig> {
    default_silo_configs_from_env(|key| std::env::var(key).ok())
}

pub fn validate_benchmark_run_silo_assignment(
    run_mode: BenchmarkRunMode,
    silo_config: &DatabaseSiloConfig,
) -> std::result::Result<BenchmarkSiloAssignment, BenchmarkIsolationError> {
    let assignment = benchmark_silo_assignment(run_mode);
    if silo_config.role != assignment.required_silo_role {
        return Err(BenchmarkIsolationError::InvalidAssignment {
            reason: format!(
                "benchmark_runner_wrong_silo:{:?}:{:?}",
                run_mode, silo_config.role
            ),
        });
    }
    let neutral_graph_features_enabled = [
        silo_config.allow_graph_routing,
        silo_config.allow_route_memory,
        silo_config.allow_canonical_graph,
        silo_config.allow_context_packet_graph,
    ]
    .contains(&true);
    if assignment.required_silo_role == DatabaseSiloRole::NeutralBenchmark
        && neutral_graph_features_enabled
    {
        return Err(BenchmarkIsolationError::InvalidAssignment {
            reason: "neutral_runner_graph_features_enabled".into(),
        });
    }
    if assignment.required_silo_role == DatabaseSiloRole::GovernedBenchmark
        && !silo_config.allow_graph_routing
    {
        return Err(BenchmarkIsolationError::InvalidAssignment {
            reason: "governed_runner_graph_routing_disabled".into(),
        });
    }
    Ok(assignment)
}

#[must_use]
pub fn benchmark_silo_assignment(run_mode: BenchmarkRunMode) -> BenchmarkSiloAssignment {
    match run_mode {
        BenchmarkRunMode::NeutralLongContext
        | BenchmarkRunMode::NeutralFlatRag
        | BenchmarkRunMode::NoMemoryLowerBound => BenchmarkSiloAssignment {
            run_mode,
            required_silo_role: DatabaseSiloRole::NeutralBenchmark,
            graph_routing_allowed: false,
            writeback_allowed: false,
            synthetic_data_allowed: true,
        },
        BenchmarkRunMode::RawDagRouting
        | BenchmarkRunMode::GovernedDagdb
        | BenchmarkRunMode::GovernedDagdbOptimized => BenchmarkSiloAssignment {
            run_mode,
            required_silo_role: DatabaseSiloRole::GovernedBenchmark,
            graph_routing_allowed: true,
            writeback_allowed: true,
            synthetic_data_allowed: true,
        },
    }
}

#[must_use]
pub fn validate_benchmark_silo_config<F>(
    configs: &[DatabaseSiloConfig],
    run_plan: &[BenchmarkRunMode],
    env_lookup: F,
) -> BenchmarkIsolationValidation
where
    F: Fn(&str) -> Option<String>,
{
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut by_role = BTreeMap::new();
    for config in configs {
        by_role.insert(config.role, config);
    }
    let main_db_protected = by_role
        .get(&DatabaseSiloRole::Main)
        .map(|config| !config.allow_benchmark_writes && !config.allow_synthetic_data)
        .unwrap_or(false);
    if !main_db_protected {
        errors.push("main_database_allows_benchmark_mutation".into());
    }

    for role in [
        DatabaseSiloRole::Main,
        DatabaseSiloRole::NeutralBenchmark,
        DatabaseSiloRole::GovernedBenchmark,
    ] {
        if !by_role.contains_key(&role) {
            errors.push(format!("missing_silo_role:{role:?}"));
        }
    }

    let mut runner_silo_assignments = Vec::new();
    for run_mode in run_plan {
        let assignment = benchmark_silo_assignment(*run_mode);
        if let Some(config) = by_role.get(&assignment.required_silo_role) {
            match validate_benchmark_run_silo_assignment(*run_mode, config) {
                Ok(guarded) => runner_silo_assignments.push(guarded),
                Err(error) => errors.push(error.to_string()),
            }
        } else {
            errors.push(format!("missing_assignment_silo:{:?}", run_mode));
        }
    }

    if let Some(neutral) = by_role.get(&DatabaseSiloRole::NeutralBenchmark) {
        if neutral.allow_graph_routing {
            errors.push("neutral_benchmark_graph_routing_enabled".into());
        }
        if neutral.allow_route_memory {
            errors.push("neutral_benchmark_route_memory_enabled".into());
        }
        if neutral.allow_canonical_graph {
            errors.push("neutral_benchmark_canonical_graph_enabled".into());
        }
        if neutral.allow_context_packet_graph {
            errors.push("neutral_benchmark_context_packet_graph_enabled".into());
        }
    }
    if let Some(governed) = by_role.get(&DatabaseSiloRole::GovernedBenchmark)
        && !governed.allow_graph_routing
    {
        errors.push("governed_benchmark_graph_routing_disabled".into());
    }

    for config in configs
        .iter()
        .filter(|config| config.configured && config.role != DatabaseSiloRole::Main)
    {
        if config.tenant_id.is_empty() {
            errors.push(format!(
                "configured_benchmark_silo_missing_tenant:{:?}",
                config.role
            ));
        }
        if config.namespace.is_empty() {
            errors.push(format!(
                "configured_benchmark_silo_missing_namespace:{:?}",
                config.role
            ));
        }
    }

    let configured_count = configs.iter().filter(|config| config.configured).count();
    if configured_count < 3 {
        warnings.push("deterministic_report_file_mode".into());
    }
    let url_values = configured_url_values(configs, &env_lookup);
    let neutral_governed_separated =
        validate_url_separation(&url_values, &mut errors, &mut warnings, configs);

    BenchmarkIsolationValidation {
        valid: errors.is_empty(),
        errors,
        warnings,
        main_db_protected,
        neutral_governed_separated,
        runner_silo_assignments,
    }
}

fn configured_url_values<F>(
    configs: &[DatabaseSiloConfig],
    env_lookup: &F,
) -> BTreeMap<DatabaseSiloRole, String>
where
    F: Fn(&str) -> Option<String>,
{
    configs
        .iter()
        .filter_map(|config| {
            env_lookup(config.database_url_env.as_str()).map(|url| (config.role, url))
        })
        .collect()
}

fn validate_url_separation(
    url_values: &BTreeMap<DatabaseSiloRole, String>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    configs: &[DatabaseSiloConfig],
) -> bool {
    // Compare canonicalized URLs, not raw strings: two URLs that differ only by
    // port, case, scheme alias, or query-param order point at the SAME database
    // and must be reported as NOT separated. An unparseable URL is a hard error,
    // never a soft warning, so a malformed silo URL cannot pass isolation.
    let normalize = |role: &DatabaseSiloRole, errors: &mut Vec<String>| -> Option<String> {
        let raw = url_values.get(role)?;
        match normalize_database_url(raw) {
            Some(canonical) => Some(canonical),
            None => {
                errors.push(format!("benchmark_silo_url_unparseable:{role:?}"));
                None
            }
        }
    };
    let neutral = normalize(&DatabaseSiloRole::NeutralBenchmark, errors);
    let governed = normalize(&DatabaseSiloRole::GovernedBenchmark, errors);
    let main = normalize(&DatabaseSiloRole::Main, errors);

    let mut separated = match (
        url_values.get(&DatabaseSiloRole::NeutralBenchmark),
        url_values.get(&DatabaseSiloRole::GovernedBenchmark),
    ) {
        (Some(_), Some(_)) => match (&neutral, &governed) {
            (Some(neutral_url), Some(governed_url)) => {
                if neutral_url == governed_url {
                    errors.push("neutral_and_governed_database_urls_match".into());
                    false
                } else {
                    true
                }
            }
            // At least one of the two configured URLs failed to parse; the hard
            // error above already records it, and separation is unproven.
            _ => false,
        },
        _ => {
            warnings.push("neutral_governed_separation_unobservable".into());
            false
        }
    };
    let benchmark_writes_enabled = configs
        .iter()
        .any(|config| config.role != DatabaseSiloRole::Main && config.allow_benchmark_writes);
    if benchmark_writes_enabled {
        match url_values.get(&DatabaseSiloRole::Main) {
            Some(_) => {
                if let Some(main_url) = &main
                    && (neutral
                        .as_ref()
                        .is_some_and(|neutral_url| neutral_url == main_url)
                        || governed
                            .as_ref()
                            .is_some_and(|governed_url| governed_url == main_url))
                {
                    separated = false;
                    errors.push("main_and_benchmark_database_urls_match".into());
                }
            }
            None => warnings.push("main_benchmark_separation_unobservable".into()),
        }
    }
    separated
}

/// Canonicalize a database URL so equivalent URLs compare equal.
///
/// No `url` crate is available in this crate's dependencies, so this does a
/// careful manual canonicalization of the parts that determine which database an
/// URL points at: the scheme (with `postgres`/`postgresql` treated as aliases),
/// the lowercased host, the explicit port (default-filled for known schemes), the
/// path / database name, and the query parameters in sorted order. Returns `None`
/// when the URL cannot be parsed, which the caller treats as a hard error.
fn normalize_database_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (scheme_raw, rest) = trimmed.split_once("://")?;
    if scheme_raw.is_empty() || rest.is_empty() {
        return None;
    }
    let scheme = match scheme_raw.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" => "postgresql".to_owned(),
        other => other.to_owned(),
    };

    // Split authority (userinfo@host:port) from path?query.
    let (authority, path_and_query) = match rest.split_once('/') {
        Some((authority, tail)) => (authority, format!("/{tail}")),
        None => (rest, String::new()),
    };
    if authority.is_empty() {
        return None;
    }

    // Drop userinfo: credentials do not change which database the URL targets.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let (host, port) = match host_port.rsplit_once(':') {
        // A ':' inside brackets is an IPv6 host, not a port separator.
        Some((host, port)) if !host.ends_with(']') => {
            let port = port.parse::<u16>().ok()?;
            (host, Some(port))
        }
        _ => (host_port, None),
    };
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let port = port.unwrap_or_else(|| default_port_for_scheme(&scheme));

    // Split path from query and canonicalize the query param order.
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (path_and_query, String::new()),
    };
    let mut params: Vec<&str> = query.split('&').filter(|param| !param.is_empty()).collect();
    params.sort_unstable();
    let canonical_query = params.join("&");

    Some(format!("{scheme}://{host}:{port}{path}?{canonical_query}"))
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "postgresql" => 5432,
        "mysql" => 3306,
        "redis" => 6379,
        "mongodb" => 27017,
        _ => 0,
    }
}

#[must_use]
pub fn build_contamination_check(
    checked_at_commit_or_run_id: String,
    evidence: &ContaminationEvidence,
) -> SiloContaminationCheck {
    let main_db_used_for_benchmark =
        contamination_status(evidence.demo_mode, evidence.main_db_used_for_benchmark);
    let neutral_used_graph_routing =
        contamination_status(evidence.demo_mode, evidence.neutral_used_graph_routing);
    let governed_used_neutral_state =
        contamination_status(evidence.demo_mode, evidence.governed_used_neutral_state);
    let cross_silo_route_memory_reuse =
        contamination_status(evidence.demo_mode, evidence.cross_silo_route_memory_reuse);
    let cross_silo_context_packet_reuse =
        contamination_status(evidence.demo_mode, evidence.cross_silo_context_packet_reuse);
    let cross_silo_receipt_reuse =
        contamination_status(evidence.demo_mode, evidence.cross_silo_receipt_reuse);
    let statuses = [
        main_db_used_for_benchmark,
        neutral_used_graph_routing,
        governed_used_neutral_state,
        cross_silo_route_memory_reuse,
        cross_silo_context_packet_reuse,
        cross_silo_receipt_reuse,
    ];
    let contamination_detected = statuses.contains(&SiloContaminationStatus::Contaminated);
    let findings = if evidence.demo_mode {
        vec!["not_configured_demo_mode".into()]
    } else {
        statuses
            .contains(&SiloContaminationStatus::UnknownNotObservable)
            .then(|| "one_or_more_fields_unknown_not_observable".into())
            .into_iter()
            .collect()
    };
    SiloContaminationCheck {
        checked_at_commit_or_run_id,
        main_db_used_for_benchmark,
        neutral_used_graph_routing,
        governed_used_neutral_state,
        cross_silo_route_memory_reuse,
        cross_silo_context_packet_reuse,
        cross_silo_receipt_reuse,
        contamination_detected,
        findings,
    }
}

fn contamination_status(demo_mode: bool, evidence: Option<bool>) -> SiloContaminationStatus {
    if demo_mode {
        return SiloContaminationStatus::NotConfiguredDemoMode;
    }
    match evidence {
        Some(false) => SiloContaminationStatus::Clean,
        Some(true) => SiloContaminationStatus::Contaminated,
        None => SiloContaminationStatus::UnknownNotObservable,
    }
}

#[must_use]
pub fn unobservable_contamination_evidence(demo_mode: bool) -> ContaminationEvidence {
    ContaminationEvidence {
        demo_mode,
        main_db_used_for_benchmark: None,
        neutral_used_graph_routing: None,
        governed_used_neutral_state: None,
        cross_silo_route_memory_reuse: None,
        cross_silo_context_packet_reuse: None,
        cross_silo_receipt_reuse: None,
    }
}

pub fn build_benchmark_isolation_report<F>(
    diagnostic_report_dir: &Path,
    source_commit_or_run_id: String,
    env_lookup: F,
) -> BenchmarkIsolationReport
where
    F: Fn(&str) -> Option<String>,
{
    let configs = default_silo_configs_from_env(&env_lookup);
    let validation =
        validate_benchmark_silo_config(&configs, &all_benchmark_run_modes(), &env_lookup);
    let demo_mode = configs.iter().any(|config| !config.configured);
    let contamination_check = build_contamination_check(
        source_commit_or_run_id.clone(),
        &unobservable_contamination_evidence(demo_mode),
    );
    let source_artifacts = source_artifact_paths();
    let hashes = artifact_hashes(diagnostic_report_dir, &source_artifacts);
    let fixture_id = fixture_id_from_summary(diagnostic_report_dir)
        .unwrap_or_else(|| "missing_diagnostic_fixture".into());
    let report_id_material =
        format!("{REPORT_SCHEMA_VERSION}:{source_commit_or_run_id}:{fixture_id}");
    let report_id = Hash256::digest(report_id_material.as_bytes()).to_string();
    BenchmarkIsolationReport {
        schema_version: REPORT_SCHEMA_VERSION.into(),
        report_id,
        fixture_id,
        main_silo_status: config_by_role(&configs, DatabaseSiloRole::Main),
        neutral_silo_status: config_by_role(&configs, DatabaseSiloRole::NeutralBenchmark),
        governed_silo_status: config_by_role(&configs, DatabaseSiloRole::GovernedBenchmark),
        validation,
        contamination_check,
        diagnostic_report_ids: hashes
            .values()
            .filter_map(|hash| hash.hash.clone())
            .collect(),
        generated_at_harness_run_id: source_commit_or_run_id.clone(),
        diagnostic_summary_hash: hash_by_name(&hashes, SUMMARY_JSON),
        per_task_results_hash: hash_by_name(&hashes, PER_TASK_RESULTS_JSON),
        cost_breakdown_hash: hash_by_name(&hashes, COST_BREAKDOWN_JSON),
        quality_breakdown_hash: hash_by_name(&hashes, QUALITY_BREAKDOWN_JSON),
        latency_breakdown_hash: hash_by_name(&hashes, LATENCY_BREAKDOWN_JSON),
        recommendations_hash: hash_by_name(&hashes, RECOMMENDATIONS_MD),
        source_artifact_paths: source_artifacts,
        source_commit_or_run_id,
    }
}

fn config_by_role(configs: &[DatabaseSiloConfig], role: DatabaseSiloRole) -> DatabaseSiloConfig {
    configs
        .iter()
        .find(|config| config.role == role)
        .cloned()
        .unwrap_or(DatabaseSiloConfig {
            role,
            purpose: match role {
                DatabaseSiloRole::Main => DatabaseSiloPurpose::ProductionMemory,
                DatabaseSiloRole::NeutralBenchmark => DatabaseSiloPurpose::NeutralBaseline,
                DatabaseSiloRole::GovernedBenchmark => DatabaseSiloPurpose::GovernedDagBenchmark,
            },
            database_url_env: String::new(),
            configured: false,
            tenant_id: String::new(),
            namespace: String::new(),
            read_only: true,
            allow_benchmark_writes: false,
            allow_synthetic_data: false,
            allow_graph_routing: false,
            allow_route_memory: false,
            allow_canonical_graph: false,
            allow_context_packet_graph: false,
            allow_private_payload_reads: false,
        })
}

fn source_artifact_paths() -> Vec<String> {
    [
        SUMMARY_JSON,
        PER_TASK_RESULTS_JSON,
        COST_BREAKDOWN_JSON,
        QUALITY_BREAKDOWN_JSON,
        LATENCY_BREAKDOWN_JSON,
        RECOMMENDATIONS_MD,
    ]
    .into_iter()
    .map(|artifact| format!("{E2E_DIAGNOSTIC_DIR}/{artifact}"))
    .collect()
}

fn artifact_hashes(
    diagnostic_report_dir: &Path,
    source_artifacts: &[String],
) -> BTreeMap<String, ArtifactHashStatus> {
    source_artifacts
        .iter()
        .map(|source_path| {
            let name = source_path
                .rsplit('/')
                .next()
                .unwrap_or(source_path.as_str());
            let path = diagnostic_report_dir.join(name);
            let status = match fs::read(&path) {
                Ok(bytes) => ArtifactHashStatus {
                    path: source_path.clone(),
                    status: "available".into(),
                    hash: Some(Hash256::digest(&bytes).to_string()),
                },
                Err(_) => ArtifactHashStatus {
                    path: source_path.clone(),
                    status: "missing".into(),
                    hash: None,
                },
            };
            (name.into(), status)
        })
        .collect()
}

fn hash_by_name(hashes: &BTreeMap<String, ArtifactHashStatus>, name: &str) -> ArtifactHashStatus {
    hashes.get(name).cloned().unwrap_or(ArtifactHashStatus {
        path: format!("{E2E_DIAGNOSTIC_DIR}/{name}"),
        status: "missing".into(),
        hash: None,
    })
}

fn fixture_id_from_summary(diagnostic_report_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(diagnostic_report_dir.join(SUMMARY_JSON)).ok()?;
    let value = serde_json::from_str::<Value>(&text).ok()?;
    value
        .get("fixture_ids")?
        .as_array()?
        .first()?
        .as_str()
        .map(str::to_owned)
}

pub fn render_benchmark_isolation_artifacts(
    report: &BenchmarkIsolationReport,
) -> std::result::Result<BenchmarkIsolationArtifacts, BenchmarkIsolationError> {
    Ok(BenchmarkIsolationArtifacts {
        silo_config_summary_json: json_string(&vec![
            &report.main_silo_status,
            &report.neutral_silo_status,
            &report.governed_silo_status,
        ])?,
        silo_validation_report_json: json_string(&report.validation)?,
        silo_contamination_report_json: json_string(&report.contamination_check)?,
        runner_silo_assignment_json: json_string(&report.validation.runner_silo_assignments)?,
        benchmark_isolation_summary_md: benchmark_isolation_markdown(report),
    })
}

pub fn write_benchmark_isolation_artifacts_for_report_dir<F>(
    diagnostic_report_dir: &Path,
    source_commit_or_run_id: String,
    env_lookup: F,
) -> std::result::Result<BenchmarkIsolationArtifacts, BenchmarkIsolationError>
where
    F: Fn(&str) -> Option<String>,
{
    let report = build_benchmark_isolation_report(
        diagnostic_report_dir,
        source_commit_or_run_id,
        env_lookup,
    );
    let artifacts = render_benchmark_isolation_artifacts(&report)?;
    write_artifact(
        SILO_CONFIG_SUMMARY_JSON,
        &artifacts.silo_config_summary_json,
    )?;
    write_artifact(
        SILO_VALIDATION_REPORT_JSON,
        &artifacts.silo_validation_report_json,
    )?;
    write_artifact(
        SILO_CONTAMINATION_REPORT_JSON,
        &artifacts.silo_contamination_report_json,
    )?;
    write_artifact(
        RUNNER_SILO_ASSIGNMENT_JSON,
        &artifacts.runner_silo_assignment_json,
    )?;
    write_artifact(
        BENCHMARK_ISOLATION_SUMMARY_MD,
        &artifacts.benchmark_isolation_summary_md,
    )?;
    Ok(artifacts)
}

pub fn write_default_benchmark_isolation_artifacts()
-> std::result::Result<BenchmarkIsolationArtifacts, BenchmarkIsolationError> {
    let report_dir = workspace_artifact_path(E2E_DIAGNOSTIC_DIR);
    write_benchmark_isolation_artifacts_for_report_dir(
        &report_dir,
        "dagdb_benchmark_isolation_report_file_mode_v1".into(),
        |key| std::env::var(key).ok(),
    )
}

fn json_string<T: Serialize>(value: &T) -> std::result::Result<String, BenchmarkIsolationError> {
    let mut json = serde_json::to_string_pretty(value)
        .map_err(|source| BenchmarkIsolationError::Json { source })?;
    json.push('\n');
    Ok(json)
}

fn benchmark_isolation_markdown(report: &BenchmarkIsolationReport) -> String {
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB Benchmark Isolation Summary\n\n");
    output.push_str(&format!("- schema_version: {}\n", report.schema_version));
    output.push_str(&format!("- report_id: {}\n", report.report_id));
    output.push_str(&format!("- fixture_id: {}\n", report.fixture_id));
    output.push_str(&format!(
        "- source_commit_or_run_id: {}\n",
        report.source_commit_or_run_id
    ));
    output.push_str(&format!("- valid: {}\n", report.validation.valid));
    output.push_str(&format!(
        "- main_db_protected: {}\n",
        report.validation.main_db_protected
    ));
    output.push_str(&format!(
        "- neutral_governed_separated: {}\n",
        report.validation.neutral_governed_separated
    ));
    output.push_str(&format!(
        "- contamination_detected: {}\n\n",
        report.contamination_check.contamination_detected
    ));
    output.push_str("## Silo Roles\n\n");
    for config in [
        &report.main_silo_status,
        &report.neutral_silo_status,
        &report.governed_silo_status,
    ] {
        output.push_str(&format!(
            "- {:?}: purpose={:?}, configured={}, env_var=not_serialized, graph_routing={}, route_memory={}, canonical_graph={}, context_packet_graph={}, benchmark_writes={}, synthetic_data={}\n",
            config.role,
            config.purpose,
            config.configured,
            config.allow_graph_routing,
            config.allow_route_memory,
            config.allow_canonical_graph,
            config.allow_context_packet_graph,
            config.allow_benchmark_writes,
            config.allow_synthetic_data
        ));
    }
    output.push_str("\n## Validation Errors\n\n");
    if report.validation.errors.is_empty() {
        output.push_str("- none\n");
    } else {
        for error in &report.validation.errors {
            output.push_str(&format!("- {error}\n"));
        }
    }
    output.push_str("\n## Validation Warnings\n\n");
    if report.validation.warnings.is_empty() {
        output.push_str("- none\n");
    } else {
        for warning in &report.validation.warnings {
            output.push_str(&format!("- {warning}\n"));
        }
    }
    output.push_str("\n## Source Artifact Hashes\n\n");
    for artifact in [
        &report.diagnostic_summary_hash,
        &report.per_task_results_hash,
        &report.cost_breakdown_hash,
        &report.quality_breakdown_hash,
        &report.latency_breakdown_hash,
        &report.recommendations_hash,
    ] {
        output.push_str(&format!(
            "- {}: status={}, hash={}\n",
            artifact.path,
            artifact.status,
            artifact.hash.as_deref().unwrap_or("missing")
        ));
    }
    output
}

fn write_artifact(path: &str, contents: &str) -> std::result::Result<(), BenchmarkIsolationError> {
    let artifact_path = workspace_artifact_path(path);
    if let Some(parent) = artifact_path.parent() {
        fs::create_dir_all(parent).map_err(|source| BenchmarkIsolationError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(&artifact_path, contents).map_err(|source| BenchmarkIsolationError::Io {
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
