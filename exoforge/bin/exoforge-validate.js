#!/usr/bin/env node

/**
 * exoforge-validate — Run constitutional validation against the ExoChain kernel.
 *
 * Loads the WASM governance kernel and runs:
 *   1. All 10 TNC enforcement checks
 *   2. Constitutional invariant verification
 *   3. Audit chain integrity verification
 *
 * Exit code 0 on all checks passing, 1 on any failure.
 *
 * Usage:
 *   exoforge-validate [--json] [--verbose] [--tnc-only] [--invariants-only]
 */

import {
  loadKernel,
  enforceAllTnc,
  collectTncViolations,
  verifyInvariants,
  auditVerify,
  workflowStages
} from '../lib/constitutional.js';

// ── Parse CLI arguments ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { json: false, verbose: false, tncOnly: false, invariantsOnly: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--json':
        args.json = true;
        break;
      case '--verbose':
      case '-v':
        args.verbose = true;
        break;
      case '--tnc-only':
        args.tncOnly = true;
        break;
      case '--invariants-only':
        args.invariantsOnly = true;
        break;
      case '--help':
      case '-h':
        console.log(`Usage: exoforge-validate [options]

Options:
  --json              Output as JSON
  --verbose, -v       Show detailed check output
  --tnc-only          Only run TNC enforcement checks
  --invariants-only   Only run invariant checks
  -h, --help          Show this help`);
        process.exit(0);
    }
  }
  return args;
}

// ── Validation checks ───────────────────────────────────────────────────────

/**
 * Build a minimal test decision + flags context for TNC validation.
 * This exercises the TNC enforcement path with a baseline decision.
 */
function buildTestContext() {
  return {
    decision: {
      id: 'validation-check-' + Date.now(),
      title: 'ExoForge Validation Check',
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
}

/**
 * Build a test invariant request context.
 */
function buildInvariantContext() {
  return {
    actor_did: 'did:exo:exoforge-validator',
    action: 'validate',
    resource: 'constitutional-invariants',
    context: {
      source: 'exoforge-validate',
      timestamp: Date.now()
    }
  };
}

/**
 * Run all validation checks and collect results.
 */
function runValidation(args) {
  const results = {
    kernel_loaded: false,
    checks: [],
    summary: { total: 0, passed: 0, failed: 0, skipped: 0 },
    validated_at: new Date().toISOString()
  };

  // Step 0: Load kernel
  try {
    const kernel = loadKernel();
    results.kernel_loaded = true;
    results.checks.push({
      name: 'kernel_load',
      category: 'infrastructure',
      status: 'pass',
      details: 'WASM governance kernel loaded successfully'
    });
    results.summary.total++;
    results.summary.passed++;
  } catch (err) {
    results.checks.push({
      name: 'kernel_load',
      category: 'infrastructure',
      status: 'fail',
      details: `Failed to load WASM kernel: ${err.message}`
    });
    results.summary.total++;
    results.summary.failed++;
    return results;
  }

  // Step 1: Workflow stages (sanity check)
  if (!args.invariantsOnly) {
    try {
      const stages = workflowStages();
      const stageNames = Array.isArray(stages) ? stages : Object.keys(stages);
      results.checks.push({
        name: 'workflow_stages',
        category: 'bcts',
        status: 'pass',
        details: `BCTS lifecycle has ${stageNames.length} stages: ${stageNames.join(', ')}`
      });
      results.summary.total++;
      results.summary.passed++;
    } catch (err) {
      results.checks.push({
        name: 'workflow_stages',
        category: 'bcts',
        status: 'fail',
        details: `Workflow stages check failed: ${err.message}`
      });
      results.summary.total++;
      results.summary.failed++;
    }
  }

  // Step 2: TNC enforcement (all 10)
  if (!args.invariantsOnly) {
    const ctx = buildTestContext();

    // Test enforceAllTnc (short-circuit mode)
    const tncResult = enforceAllTnc(ctx);
    results.checks.push({
      name: 'tnc_enforce_all',
      category: 'tnc',
      status: tncResult.ok ? 'pass' : 'fail',
      details: tncResult.ok
        ? 'All 10 TNCs passed enforcement check'
        : `TNC enforcement failed: ${tncResult.violation}`
    });
    results.summary.total++;
    if (tncResult.ok) results.summary.passed++;
    else results.summary.failed++;

    // Test collectTncViolations (exhaustive mode)
    try {
      const violations = collectTncViolations(ctx);
      const violationList = violations.violations || violations;
      const count = Array.isArray(violationList) ? violationList.length : 0;
      results.checks.push({
        name: 'tnc_collect_violations',
        category: 'tnc',
        status: count === 0 ? 'pass' : 'fail',
        details: count === 0
          ? 'Zero TNC violations detected (exhaustive scan)'
          : `${count} TNC violation(s) detected`,
        violations: count > 0 ? violationList : undefined
      });
      results.summary.total++;
      if (count === 0) results.summary.passed++;
      else results.summary.failed++;
    } catch (err) {
      results.checks.push({
        name: 'tnc_collect_violations',
        category: 'tnc',
        status: 'fail',
        details: `TNC violation collection failed: ${err.message}`
      });
      results.summary.total++;
      results.summary.failed++;
    }

    // Test individual TNC flags by toggling each to false
    if (args.verbose) {
      const tncNames = [
        'authority_chain_verified', 'human_gate_satisfied', 'consent_verified',
        'identity_verified', 'delegation_unexpired', 'constitutional_binding_valid',
        'quorum_met', 'terminal_immutable', 'ai_ceiling_respected',
        'evidence_bundle_complete'
      ];
      for (let i = 0; i < tncNames.length; i++) {
        const flagName = tncNames[i];
        const testFlags = { ...ctx.flags, [flagName]: false };
        const testResult = enforceAllTnc({ decision: ctx.decision, flags: testFlags });
        results.checks.push({
          name: `tnc_${String(i + 1).padStart(2, '0')}_${flagName}`,
          category: 'tnc_detail',
          status: testResult.ok ? 'warn' : 'pass', // Should FAIL when flag is false
          details: testResult.ok
            ? `WARNING: TNC-${String(i + 1).padStart(2, '0')} did not reject when ${flagName} was false`
            : `TNC-${String(i + 1).padStart(2, '0')} correctly rejected: ${testResult.violation}`
        });
        results.summary.total++;
        // A pass here means the TNC correctly rejected the bad flag
        if (!testResult.ok) results.summary.passed++;
        else results.summary.failed++;
      }
    }
  }

  // Step 3: Invariant enforcement
  if (!args.tncOnly) {
    const invCtx = buildInvariantContext();
    const invResult = verifyInvariants(invCtx);
    results.checks.push({
      name: 'invariant_enforcement',
      category: 'invariants',
      status: invResult.ok ? 'pass' : 'fail',
      details: invResult.ok
        ? `Invariant enforcement passed (${invResult.violations.length} violations)`
        : `Invariant enforcement failed: ${invResult.violations.join(', ')}`
    });
    results.summary.total++;
    if (invResult.ok && invResult.violations.length === 0) results.summary.passed++;
    else if (invResult.ok) {
      results.summary.passed++; // Passed but with warnings
    } else {
      results.summary.failed++;
    }
  }

  // Step 4: Audit chain verification (empty chain baseline)
  if (!args.tncOnly) {
    const emptyChain = auditVerify([]);
    results.checks.push({
      name: 'audit_chain_empty',
      category: 'audit',
      status: emptyChain.ok ? 'pass' : 'fail',
      details: emptyChain.ok
        ? 'Empty audit chain baseline verified'
        : `Audit chain verification failed: ${emptyChain.error}`
    });
    results.summary.total++;
    if (emptyChain.ok) results.summary.passed++;
    else results.summary.failed++;
  }

  return results;
}

// ── Output formatting ───────────────────────────────────────────────────────

function formatTextReport(results) {
  const lines = [];
  lines.push('');
  lines.push('  ExoForge Constitutional Validation Report');
  lines.push(`  ${'='.repeat(50)}`);
  lines.push(`  Kernel loaded: ${results.kernel_loaded ? 'YES' : 'NO'}`);
  lines.push('');

  // Group checks by category
  const categories = {};
  for (const check of results.checks) {
    if (!categories[check.category]) categories[check.category] = [];
    categories[check.category].push(check);
  }

  for (const [category, checks] of Object.entries(categories)) {
    lines.push(`  --- ${category.toUpperCase()} ---`);
    for (const check of checks) {
      const icon = check.status === 'pass' ? '[PASS]'
        : check.status === 'warn' ? '[WARN]'
        : '[FAIL]';
      lines.push(`  ${icon} ${check.name}: ${check.details}`);
      if (check.violations) {
        for (const v of check.violations) {
          lines.push(`         - ${typeof v === 'string' ? v : JSON.stringify(v)}`);
        }
      }
    }
    lines.push('');
  }

  lines.push('  --- SUMMARY ---');
  lines.push(`  Total checks: ${results.summary.total}`);
  lines.push(`  Passed: ${results.summary.passed}`);
  lines.push(`  Failed: ${results.summary.failed}`);
  lines.push(`  Skipped: ${results.summary.skipped}`);
  lines.push(`  Result: ${results.summary.failed === 0 ? 'ALL CHECKS PASSED' : 'VALIDATION FAILED'}`);
  lines.push(`  Validated at: ${results.validated_at}`);
  lines.push('');

  return lines.join('\n');
}

// ── Main ────────────────────────────────────────────────────────────────────

function main() {
  const args = parseArgs(process.argv);

  const results = runValidation(args);

  if (args.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log(formatTextReport(results));
  }

  process.exit(results.summary.failed > 0 ? 1 : 0);
}

main();
