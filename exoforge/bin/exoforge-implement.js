#!/usr/bin/env node

/**
 * exoforge-implement — Generate an implementation readiness plan from a GitHub issue.
 *
 * Reads the specified issue from GitHub, analyzes its requirements against
 * the 5-panel governance matrix, and produces a structured implementation
 * plan skeleton. The plan includes affected files, governance gates,
 * required reviews, and testing criteria. This command is planning-only.
 *
 * Usage:
 *   exoforge-implement <issue_number> [--repo owner/name] [--json]
 */

import { getIssue } from '../lib/github.js';
import {
  REVIEW_BINDING,
  REVIEW_TIMESTAMP_ISO,
  getPanels,
  conductReview,
  tallyVotes
} from '../lib/panels.js';

const DEFAULT_REPO = 'exochain/exochain';

// ── Parse CLI arguments ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { issueNumber: null, repo: DEFAULT_REPO, json: false, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--repo':
        args.repo = argv[++i];
        break;
      case '--json':
        args.json = true;
        break;
      case '--dry-run':
        args.dryRun = true;
        break;
      case '--help':
      case '-h':
        console.log(`Usage: exoforge-implement <issue_number> [options]

Arguments:
  issue_number            GitHub issue number to implement

Options:
  --repo <owner/name>     Repository (default: ${DEFAULT_REPO})
  --json                  Output as JSON
  --dry-run               Generate plan without GitHub interaction
  -h, --help              Show this help`);
        process.exit(0);
      default:
        if (!argv[i].startsWith('--') && !args.issueNumber) {
          args.issueNumber = parseInt(argv[i], 10);
        }
    }
  }
  return args;
}

// ── File impact analysis ────────────────────────────────────────────────────

/**
 * Map of keyword patterns to likely affected file paths.
 */
const FILE_IMPACT_MAP = {
  governance: [
    'crates/exo-gatekeeper/src/',
    'packages/exochain-wasm/src/',
    'command-base/app/services/governance.js',
    'command-base/app/routes/governance.js'
  ],
  legal: [
    'crates/exo-legal/src/',
    'crates/exo-gatekeeper/src/legal/',
    'packages/exochain-wasm/src/legal.rs'
  ],
  security: [
    'crates/exo-sentinel/src/',
    'crates/exo-gatekeeper/src/pace/',
    'command-base/app/services/governance.js'
  ],
  wasm: [
    'packages/exochain-wasm/src/lib.rs',
    'packages/exochain-wasm/wasm/',
    'crates/'
  ],
  api: [
    'command-base/app/routes/',
    'command-base/app/services/',
    'command-base/app/server.js'
  ],
  database: [
    'command-base/app/server.js',
    'command-base/app/routes/',
    'init-db.sh'
  ],
  frontend: [
    'command-base/app/public/app.js',
    'command-base/app/public/index.html',
    'web/'
  ],
  deploy: [
    'Dockerfile',
    'docker-compose.yml',
    'deploy/',
    '.github/workflows/'
  ],
  test: [
    'crates/*/tests/',
    'command-base/test/',
    'tarpaulin.toml'
  ]
};

/**
 * Analyze an issue to determine likely affected files.
 */
function analyzeFileImpact(issue) {
  const text = `${issue.title || ''} ${issue.body || ''}`.toLowerCase();
  const affected = new Set();

  for (const [keyword, paths] of Object.entries(FILE_IMPACT_MAP)) {
    if (text.includes(keyword)) {
      for (const p of paths) affected.add(p);
    }
  }

  // Always include test paths for implementation
  affected.add('crates/*/tests/');

  return Array.from(affected).sort();
}

/**
 * Extract implementation requirements from issue body.
 */
function extractRequirements(issue) {
  const body = issue.body || '';
  const requirements = [];

  // Look for checkbox items
  const checkboxPattern = /- \[[ x]\] (.+)/g;
  let match;
  while ((match = checkboxPattern.exec(body)) !== null) {
    requirements.push({
      text: match[1].trim(),
      completed: match[0].includes('[x]')
    });
  }

  // Look for "Requirements:" or "Acceptance Criteria:" sections
  const sectionPattern = /(?:requirements?|acceptance criteria|todo|tasks?):\s*\n((?:[-*] .+\n?)+)/gi;
  while ((match = sectionPattern.exec(body)) !== null) {
    const items = match[1].split('\n').filter(l => l.trim().startsWith('-') || l.trim().startsWith('*'));
    for (const item of items) {
      const text = item.replace(/^[-*]\s*/, '').trim();
      if (text && !requirements.some(r => r.text === text)) {
        requirements.push({ text, completed: false });
      }
    }
  }

  return requirements;
}

/**
 * Determine implementation phases based on issue analysis.
 */
function determinePhases(issue, panelAssessments) {
  const phases = [];

  // Phase 1: Governance clearance
  const govAssessment = panelAssessments.find(a => a.panel === 'Governance');
  const secAssessment = panelAssessments.find(a => a.panel === 'Security');

  phases.push({
    number: 1,
    name: 'Governance Clearance',
    description: 'Verify authority chain, TNC compliance, and obtain council approval',
    tasks: [
      'Run exoforge-validate to confirm kernel health',
      'Run exoforge-council-review with implementation proposal',
      'Obtain required panel approvals',
      ...(govAssessment && govAssessment.vote === 'reject' ?
        ['BLOCKED: Governance panel rejected — resolve before proceeding'] : [])
    ],
    blocked: govAssessment && govAssessment.vote === 'reject'
  });

  // Phase 2: Implementation
  phases.push({
    number: 2,
    name: 'Implementation',
    description: 'Write code changes guided by issue requirements',
    tasks: [
      'Create feature branch from main',
      'Implement changes per requirements',
      'Update WASM bindings if Rust crates are modified',
      'Run cargo test and cargo clippy'
    ],
    blocked: false
  });

  // Phase 3: Validation
  phases.push({
    number: 3,
    name: 'Validation',
    description: 'Run constitutional validation and security checks',
    tasks: [
      'Run exoforge-validate --verbose',
      'Run exoforge-council-review on completed changes',
      'Verify governance receipt chain integrity',
      ...(secAssessment && secAssessment.criteria_failed.length > 0 ?
        ['Security review required: ' + secAssessment.criteria_failed.join('; ')] : [])
    ],
    blocked: false
  });

  // Phase 4: Submission
  phases.push({
    number: 4,
    name: 'Submission',
    description: 'Create PR with governance attestation',
    tasks: [
      'Create pull request with implementation summary',
      'Attach governance receipt chain',
      'Request panel reviews per classification',
      'Await CI and constitutional validation checks'
    ],
    blocked: false
  });

  return phases;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  if (!args.issueNumber) {
    console.error('Error: issue number is required. Usage: exoforge-implement <issue_number>');
    process.exit(1);
  }

  try {
    // Fetch issue
    let issue;
    if (args.dryRun) {
      issue = {
        number: args.issueNumber,
        title: `Dry-run issue #${args.issueNumber}`,
        body: 'This is a dry-run implementation plan.',
        labels: [],
        state: 'open',
        url: `https://github.com/${args.repo}/issues/${args.issueNumber}`
      };
    } else {
      issue = getIssue(args.repo, args.issueNumber);
    }

    // Run panel analysis
    const panels = getPanels();
    const proposal = {
      title: issue.title,
      description: issue.body || '',
      type: 'feature',
      affectedSystems: (issue.labels || []).map(l => l.name || l),
      author: issue.author ? (issue.author.login || issue.author) : 'unknown'
    };
    const assessments = conductReview(panels, proposal);
    const tally = tallyVotes(assessments);

    // Analyze file impact
    const affectedFiles = analyzeFileImpact(issue);

    // Extract requirements
    const requirements = extractRequirements(issue);

    // Determine phases
    const phases = determinePhases(issue, assessments);

    // Build implementation plan
    const plan = {
      issue: {
        number: issue.number,
        title: issue.title,
        url: issue.url,
        state: issue.state,
        labels: (issue.labels || []).map(l => l.name || l)
      },
      governance: {
        verdict: tally.verdict,
        score: tally.score,
        vetoed_by: tally.vetoed_by,
        panel_summary: tally.breakdown
      },
      affected_files: affectedFiles,
      requirements,
      phases,
      branch_name: `exoforge/issue-${issue.number}`,
      estimated_complexity: tally.total_findings > 5 ? 'high'
        : tally.total_findings > 2 ? 'medium' : 'low',
      requires_wasm_rebuild: affectedFiles.some(f => f.includes('crates/') || f.includes('wasm')),
      requires_council_review: tally.verdict !== 'APPROVED',
      generated_at: REVIEW_TIMESTAMP_ISO,
      execution_mode: 'planning_only',
      binding_review: REVIEW_BINDING,
      planning_note: 'This command generates an implementation readiness plan; it does not modify files.'
    };

    if (args.json) {
      console.log(JSON.stringify(plan, null, 2));
    } else {
      console.log('');
      console.log('  ExoForge Implementation Readiness Plan');
      console.log(`  ${'='.repeat(50)}`);
      console.log(`  Issue: #${plan.issue.number} — ${plan.issue.title}`);
      console.log(`  URL: ${plan.issue.url}`);
      console.log(`  Branch: ${plan.branch_name}`);
      console.log(`  Complexity: ${plan.estimated_complexity}`);
      console.log(`  Council verdict: ${plan.governance.verdict} (score: ${plan.governance.score})`);
      if (plan.governance.vetoed_by) {
        console.log(`  VETOED BY: ${plan.governance.vetoed_by}`);
      }
      console.log('');

      if (plan.requirements.length > 0) {
        console.log('  Requirements:');
        for (const r of plan.requirements) {
          console.log(`    ${r.completed ? '[x]' : '[ ]'} ${r.text}`);
        }
        console.log('');
      }

      console.log('  Affected files:');
      for (const f of plan.affected_files) {
        console.log(`    - ${f}`);
      }
      console.log('');

      for (const phase of plan.phases) {
        console.log(`  Phase ${phase.number}: ${phase.name}${phase.blocked ? ' [BLOCKED]' : ''}`);
        console.log(`  ${phase.description}`);
        for (const task of phase.tasks) {
          console.log(`    - ${task}`);
        }
        console.log('');
      }

      if (plan.requires_wasm_rebuild) {
        console.log('  NOTE: This implementation requires a WASM rebuild (wasm-pack build)');
      }
      console.log(`  NOTE: ${plan.planning_note}`);
      console.log('');
    }
  } catch (err) {
    console.error(`Implementation plan failed: ${err.message}`);
    process.exit(1);
  }
}

main();
