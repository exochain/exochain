#!/usr/bin/env node

/**
 * exoforge-triage — Classify GitHub issues by the 5-panel governance matrix.
 *
 * Reads open issues from the specified repository (default: exochain/exochain),
 * analyzes each issue's title + body against the five review panels
 * (Governance, Legal, Architecture, Security, Operations), and outputs
 * a structured classification report.
 *
 * Usage:
 *   exoforge-triage [--repo owner/name] [--limit N] [--label label] [--json]
 */

import { getPanels } from '../lib/panels.js';
import { listIssues, getIssue } from '../lib/github.js';

const DEFAULT_REPO = 'exochain/exochain';

// ── Parse CLI arguments ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { repo: DEFAULT_REPO, limit: 20, label: null, json: false, issue: null };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--repo':
        args.repo = argv[++i];
        break;
      case '--limit':
        args.limit = parseInt(argv[++i], 10) || 20;
        break;
      case '--label':
        args.label = argv[++i];
        break;
      case '--json':
        args.json = true;
        break;
      case '--issue':
        args.issue = parseInt(argv[++i], 10);
        break;
      case '--help':
      case '-h':
        console.log(`Usage: exoforge-triage [options]

Options:
  --repo <owner/name>   Repository to triage (default: ${DEFAULT_REPO})
  --limit <N>           Max issues to fetch (default: 20)
  --label <label>       Filter by label
  --issue <number>      Triage a single issue by number
  --json                Output as JSON
  -h, --help            Show this help`);
        process.exit(0);
    }
  }
  return args;
}

// ── Impact keywords mapped to panels ────────────────────────────────────────

const PANEL_KEYWORDS = {
  Governance: [
    'governance', 'constitutional', 'tnc', 'quorum', 'delegation', 'authority',
    'amendment', 'voting', 'deliberation', 'human gate', 'ai ceiling',
    'consent', 'ratif', 'legislative', 'branch'
  ],
  Legal: [
    'legal', 'fiduciary', 'safe harbor', 'dgcl', 'privilege', 'evidence',
    'ediscovery', 'bailment', 'custody', 'retention', 'compliance',
    'liability', 'duty', 'record', 'disclosure', 'interested party'
  ],
  Architecture: [
    'architecture', 'wasm', 'kernel', 'merkle', 'combinator', 'holon',
    'bcts', 'state machine', 'transition', 'hash', 'event', 'did',
    'signature', 'crypto', 'api', 'schema', 'data model'
  ],
  Security: [
    'security', 'threat', 'vulnerability', 'pace', 'escalation', 'shamir',
    'secret', 'key', 'encrypt', 'attack', 'risk', 'detection', 'signal',
    'audit', 'breach', 'cve', 'exploit', 'clearance'
  ],
  Operations: [
    'operations', 'deploy', 'release', 'monitor', 'health', 'succession',
    'emergency', 'failover', 'backup', 'ci', 'cd', 'pipeline', 'docker',
    'infrastructure', 'performance', 'scale', 'log'
  ]
};

/**
 * Classify an issue against the 5-panel matrix.
 * Returns impact scores (0-1) for each panel plus overall priority.
 */
function classifyIssue(issue) {
  const text = `${issue.title || ''} ${issue.body || ''}`.toLowerCase();
  const panels = getPanels();
  const impacts = {};
  let totalImpact = 0;

  for (const panel of panels) {
    const keywords = PANEL_KEYWORDS[panel.name] || [];
    let hits = 0;
    const matchedKeywords = [];

    for (const kw of keywords) {
      if (text.includes(kw)) {
        hits++;
        matchedKeywords.push(kw);
      }
    }

    const score = Math.min(1.0, hits / Math.max(3, keywords.length * 0.4));
    impacts[panel.name] = {
      score: Math.round(score * 100) / 100,
      hits,
      matched_keywords: matchedKeywords,
      weight: panel.weight
    };
    totalImpact += score * panel.weight;
  }

  // Determine priority based on total weighted impact
  let priority;
  if (totalImpact > 0.6) priority = 'critical';
  else if (totalImpact > 0.3) priority = 'high';
  else if (totalImpact > 0.1) priority = 'medium';
  else priority = 'low';

  // Determine primary panel (highest impact)
  const primaryPanel = Object.entries(impacts)
    .sort((a, b) => b[1].score - a[1].score)[0];

  // Generate recommended labels
  const labels = [];
  for (const [name, impact] of Object.entries(impacts)) {
    if (impact.score > 0.2) labels.push(`panel:${name.toLowerCase()}`);
  }
  labels.push(`priority:${priority}`);

  return {
    issue_number: issue.number,
    issue_title: issue.title,
    issue_url: issue.url,
    priority,
    total_impact: Math.round(totalImpact * 1000) / 1000,
    primary_panel: primaryPanel ? primaryPanel[0] : 'Operations',
    impacts,
    recommended_labels: labels,
    requires_council_review: totalImpact > 0.3,
    classified_at: new Date().toISOString()
  };
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  const classifications = [];

  try {
    let issues;
    if (args.issue) {
      // Triage a single issue
      const issue = getIssue(args.repo, args.issue);
      issues = [issue];
    } else {
      // Fetch open issues
      const opts = { limit: args.limit };
      if (args.label) opts.labels = args.label;
      issues = listIssues(args.repo, opts);
    }

    if (!issues || issues.length === 0) {
      if (args.json) {
        console.log(JSON.stringify({ issues: [], message: 'No open issues found' }));
      } else {
        console.log('No open issues found.');
      }
      process.exit(0);
    }

    for (const issue of issues) {
      classifications.push(classifyIssue(issue));
    }

    // Sort by total impact (highest first)
    classifications.sort((a, b) => b.total_impact - a.total_impact);

    if (args.json) {
      console.log(JSON.stringify({
        repo: args.repo,
        total_issues: classifications.length,
        critical: classifications.filter(c => c.priority === 'critical').length,
        high: classifications.filter(c => c.priority === 'high').length,
        medium: classifications.filter(c => c.priority === 'medium').length,
        low: classifications.filter(c => c.priority === 'low').length,
        require_council_review: classifications.filter(c => c.requires_council_review).length,
        issues: classifications,
        triaged_at: new Date().toISOString()
      }, null, 2));
    } else {
      console.log(`\n  ExoForge Triage Report — ${args.repo}`);
      console.log(`  ${'='.repeat(50)}`);
      console.log(`  Issues analyzed: ${classifications.length}\n`);

      for (const c of classifications) {
        const priorityBadge = {
          critical: '[!!!]',
          high: '[!! ]',
          medium: '[!  ]',
          low: '[   ]'
        }[c.priority];

        console.log(`  ${priorityBadge} #${c.issue_number}: ${c.issue_title}`);
        console.log(`         Priority: ${c.priority.toUpperCase()} | Primary panel: ${c.primary_panel} | Impact: ${c.total_impact}`);

        const impactPanels = Object.entries(c.impacts)
          .filter(([, v]) => v.score > 0)
          .map(([name, v]) => `${name}:${v.score}`)
          .join(', ');
        if (impactPanels) {
          console.log(`         Panels: ${impactPanels}`);
        }
        if (c.requires_council_review) {
          console.log(`         >> Council review required`);
        }
        console.log('');
      }

      const summary = {
        critical: classifications.filter(c => c.priority === 'critical').length,
        high: classifications.filter(c => c.priority === 'high').length,
        medium: classifications.filter(c => c.priority === 'medium').length,
        low: classifications.filter(c => c.priority === 'low').length
      };
      console.log(`  Summary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
      console.log(`  Council reviews needed: ${classifications.filter(c => c.requires_council_review).length}`);
      console.log('');
    }
  } catch (err) {
    console.error(`Triage failed: ${err.message}`);
    process.exit(1);
  }
}

main();
