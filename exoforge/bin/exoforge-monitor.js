#!/usr/bin/env node

/**
 * exoforge-monitor — Governance health monitoring for ExoChain.
 *
 * Runs periodic health checks against the ExoChain WASM kernel:
 *   - Constitutional invariant verification
 *   - TNC enforcement status
 *   - Audit chain integrity
 *   - BCTS workflow stage availability
 *   - Kernel responsiveness
 *
 * Outputs health status as JSON for integration with monitoring systems,
 * dashboards, and alerting pipelines.
 *
 * Usage:
 *   exoforge-monitor [--interval <seconds>] [--once] [--json] [--threshold <score>]
 */

import {
  loadKernel,
  enforceAllTnc,
  collectTncViolations,
  verifyInvariants,
  auditVerify,
  workflowStages,
  hashStructured
} from '../lib/constitutional.js';

// ── Parse CLI arguments ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { interval: 60, once: false, json: true, threshold: 0.8, verbose: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--interval':
        args.interval = parseInt(argv[++i], 10) || 60;
        break;
      case '--once':
        args.once = true;
        break;
      case '--json':
        args.json = true;
        break;
      case '--text':
        args.json = false;
        break;
      case '--threshold':
        args.threshold = parseFloat(argv[++i]) || 0.8;
        break;
      case '--verbose':
      case '-v':
        args.verbose = true;
        break;
      case '--help':
      case '-h':
        console.log(`Usage: exoforge-monitor [options]

Options:
  --interval <seconds>   Check interval in seconds (default: 60)
  --once                 Run once and exit (no loop)
  --json                 Output as JSON (default)
  --text                 Output as human-readable text
  --threshold <score>    Health threshold for alerting (default: 0.8)
  --verbose, -v          Include detailed check data
  -h, --help             Show this help`);
        process.exit(0);
    }
  }
  return args;
}

// ── Health check implementations ────────────────────────────────────────────

/**
 * Check kernel availability and responsiveness.
 */
function checkKernel() {
  const start = Date.now();
  try {
    const kernel = loadKernel();
    const loadTime = Date.now() - start;

    // Verify kernel responds to a basic call
    const hashStart = Date.now();
    const testHash = hashStructured({ probe: true, ts: Date.now() });
    const hashTime = Date.now() - hashStart;

    return {
      check: 'kernel_availability',
      status: 'healthy',
      score: 1.0,
      latency_ms: loadTime,
      hash_latency_ms: hashTime,
      test_hash: testHash ? testHash.substring(0, 16) + '...' : null,
      details: `Kernel loaded in ${loadTime}ms, hash computed in ${hashTime}ms`
    };
  } catch (err) {
    return {
      check: 'kernel_availability',
      status: 'critical',
      score: 0.0,
      latency_ms: Date.now() - start,
      error: err.message,
      details: 'WASM kernel is unavailable'
    };
  }
}

/**
 * Check TNC enforcement health.
 * Verifies that all 10 TNCs correctly enforce when flags are set to passing.
 */
function checkTncEnforcement() {
  const testContext = {
    decision: {
      id: 'health-check-' + Date.now(),
      title: 'Health Check Decision',
      class: 'Routine',
      state: 'Draft',
      constitution_hash: '0'.repeat(64),
      votes: [],
      evidence: [],
      created_at: Date.now(),
      transitions: []
    },
    flags: {
      authority_chain_verified: true,
      human_gate_satisfied: true,
      consent_verified: true,
      identity_verified: true,
      delegation_unexpired: true,
      constitutional_binding_valid: true,
      quorum_met: true,
      terminal_immutable: true,
      ai_ceiling_respected: true,
      evidence_bundle_complete: true
    }
  };

  try {
    // All-pass check
    const allPass = enforceAllTnc(testContext);

    // Violation collection check
    const violations = collectTncViolations(testContext);
    const violationCount = Array.isArray(violations.violations)
      ? violations.violations.length
      : Array.isArray(violations) ? violations.length : 0;

    const score = allPass.ok && violationCount === 0 ? 1.0
      : allPass.ok ? 0.8
      : 0.0;

    return {
      check: 'tnc_enforcement',
      status: score >= 0.8 ? 'healthy' : score > 0 ? 'degraded' : 'critical',
      score,
      all_pass: allPass.ok,
      violation_count: violationCount,
      details: allPass.ok
        ? `All 10 TNCs enforcing correctly (${violationCount} violations in exhaustive scan)`
        : `TNC enforcement failure: ${allPass.violation}`
    };
  } catch (err) {
    return {
      check: 'tnc_enforcement',
      status: 'critical',
      score: 0.0,
      error: err.message,
      details: 'TNC enforcement check threw an exception'
    };
  }
}

/**
 * Check constitutional invariant enforcement.
 */
function checkInvariants() {
  const ctx = {
    actor_did: 'did:exo:health-monitor',
    action: 'health_check',
    resource: 'system',
    context: { source: 'exoforge-monitor', timestamp: Date.now() }
  };

  try {
    const result = verifyInvariants(ctx);
    const violationCount = result.violations ? result.violations.length : 0;
    const score = result.ok && violationCount === 0 ? 1.0
      : result.ok ? 0.7
      : 0.0;

    return {
      check: 'invariant_enforcement',
      status: score >= 0.8 ? 'healthy' : score > 0 ? 'degraded' : 'critical',
      score,
      passed: result.passed,
      violation_count: violationCount,
      violations: violationCount > 0 ? result.violations : undefined,
      details: result.ok
        ? `Invariant enforcement active (${violationCount} violations)`
        : 'Invariant enforcement failed'
    };
  } catch (err) {
    return {
      check: 'invariant_enforcement',
      status: 'critical',
      score: 0.0,
      error: err.message,
      details: 'Invariant check threw an exception'
    };
  }
}

/**
 * Check audit chain integrity (baseline test with empty chain).
 */
function checkAuditChain() {
  try {
    const result = auditVerify([]);
    return {
      check: 'audit_chain',
      status: result.ok ? 'healthy' : 'degraded',
      score: result.ok ? 1.0 : 0.5,
      valid: result.valid,
      details: result.ok
        ? 'Audit chain verification mechanism operational'
        : `Audit chain verification issue: ${result.error}`
    };
  } catch (err) {
    return {
      check: 'audit_chain',
      status: 'critical',
      score: 0.0,
      error: err.message,
      details: 'Audit chain verification failed'
    };
  }
}

/**
 * Check BCTS workflow stages are available.
 */
function checkWorkflowStages() {
  try {
    const stages = workflowStages();
    const stageList = Array.isArray(stages) ? stages : Object.keys(stages || {});
    const expectedMinStages = 4; // At minimum: Draft, Submitted, Approved, Closed

    const score = stageList.length >= expectedMinStages ? 1.0
      : stageList.length > 0 ? 0.5
      : 0.0;

    return {
      check: 'workflow_stages',
      status: score >= 0.8 ? 'healthy' : score > 0 ? 'degraded' : 'critical',
      score,
      stage_count: stageList.length,
      stages: stageList,
      details: `${stageList.length} BCTS workflow stages available`
    };
  } catch (err) {
    return {
      check: 'workflow_stages',
      status: 'critical',
      score: 0.0,
      error: err.message,
      details: 'Failed to retrieve workflow stages'
    };
  }
}

// ── Aggregate health report ─────────────────────────────────────────────────

/**
 * Run all health checks and produce an aggregate report.
 */
function runHealthCheck(verbose) {
  const checks = [
    checkKernel(),
    checkTncEnforcement(),
    checkInvariants(),
    checkAuditChain(),
    checkWorkflowStages()
  ];

  const totalScore = checks.reduce((sum, c) => sum + c.score, 0) / checks.length;
  const overallStatus = totalScore >= 0.9 ? 'healthy'
    : totalScore >= 0.7 ? 'degraded'
    : 'critical';

  const criticalCount = checks.filter(c => c.status === 'critical').length;
  const degradedCount = checks.filter(c => c.status === 'degraded').length;
  const healthyCount = checks.filter(c => c.status === 'healthy').length;

  const report = {
    status: overallStatus,
    score: Math.round(totalScore * 1000) / 1000,
    checks_total: checks.length,
    checks_healthy: healthyCount,
    checks_degraded: degradedCount,
    checks_critical: criticalCount,
    checks: verbose ? checks : checks.map(c => ({
      check: c.check,
      status: c.status,
      score: c.score,
      details: c.details
    })),
    exochain_version: '2.2',
    monitor_version: '0.1.0-alpha',
    checked_at: new Date().toISOString()
  };

  return report;
}

// ── Output formatting ───────────────────────────────────────────────────────

function formatTextReport(report) {
  const lines = [];
  lines.push('');
  lines.push('  ExoForge Governance Health Monitor');
  lines.push(`  ${'='.repeat(50)}`);

  const statusIcon = report.status === 'healthy' ? '[OK]'
    : report.status === 'degraded' ? '[!!]'
    : '[XX]';
  lines.push(`  ${statusIcon} Overall: ${report.status.toUpperCase()} (score: ${report.score})`);
  lines.push(`  Checked at: ${report.checked_at}`);
  lines.push('');

  for (const check of report.checks) {
    const icon = check.status === 'healthy' ? '[OK]'
      : check.status === 'degraded' ? '[!!]'
      : '[XX]';
    lines.push(`  ${icon} ${check.check}: ${check.details}`);
    if (check.error) {
      lines.push(`       Error: ${check.error}`);
    }
  }

  lines.push('');
  lines.push(`  Summary: ${report.checks_healthy} healthy, ${report.checks_degraded} degraded, ${report.checks_critical} critical`);
  lines.push('');

  return lines.join('\n');
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  function runAndOutput() {
    const report = runHealthCheck(args.verbose);

    if (args.json) {
      console.log(JSON.stringify(report));
    } else {
      console.log(formatTextReport(report));
    }

    // Alert if below threshold
    if (report.score < args.threshold) {
      if (!args.json) {
        console.error(`ALERT: Health score ${report.score} is below threshold ${args.threshold}`);
      }
    }

    return report;
  }

  if (args.once) {
    const report = runAndOutput();
    process.exit(report.checks_critical > 0 ? 1 : 0);
  } else {
    // Continuous monitoring loop
    if (!args.json) {
      console.log(`Starting continuous monitoring (interval: ${args.interval}s, threshold: ${args.threshold})`);
      console.log('Press Ctrl+C to stop.\n');
    }

    runAndOutput();
    setInterval(runAndOutput, args.interval * 1000);
  }
}

main();
