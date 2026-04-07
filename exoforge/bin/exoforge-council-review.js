#!/usr/bin/env node

/**
 * exoforge-council-review — Run a 5-panel council review on a proposal.
 *
 * Accepts a proposal description (as CLI argument or via stdin) and runs
 * it through all 5 governance panels (Governance, Legal, Architecture,
 * Security, Operations). Each panel evaluates the proposal against its
 * criteria and casts a weighted vote. The final verdict is computed using
 * weighted tallying with veto power for Security and Governance panels.
 *
 * Usage:
 *   exoforge-council-review "Add new WASM combinator for delegation"
 *   exoforge-council-review --title "Add combinator" --description "..."
 *   echo "proposal text" | exoforge-council-review --stdin
 *   exoforge-council-review --json "Modify safe harbor process"
 */

import { getPanels, conductReview, tallyVotes } from '../lib/panels.js';

// ── Parse CLI arguments ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {
    title: null,
    description: null,
    type: 'feature',
    affectedSystems: [],
    author: 'exoforge-cli',
    json: false,
    stdin: false,
    panels: null // null = all panels
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--title':
        args.title = argv[++i];
        break;
      case '--description':
      case '--desc':
        args.description = argv[++i];
        break;
      case '--type':
        args.type = argv[++i];
        break;
      case '--affected':
        args.affectedSystems = argv[++i].split(',');
        break;
      case '--author':
        args.author = argv[++i];
        break;
      case '--json':
        args.json = true;
        break;
      case '--stdin':
        args.stdin = true;
        break;
      case '--panels':
        args.panels = argv[++i].split(',').map(p => p.trim());
        break;
      case '--help':
      case '-h':
        console.log(`Usage: exoforge-council-review [options] [proposal_text]

Options:
  --title <title>         Proposal title
  --description <desc>    Proposal description (use quotes for multi-word)
  --type <type>           Proposal type: feature|bugfix|refactor|security|governance (default: feature)
  --affected <systems>    Comma-separated affected systems
  --author <name>         Author identifier (default: exoforge-cli)
  --panels <names>        Comma-separated panel names to run (default: all)
  --json                  Output as JSON
  --stdin                 Read proposal from stdin
  -h, --help              Show this help

Examples:
  exoforge-council-review "Add new WASM combinator for delegation ceiling enforcement"
  exoforge-council-review --title "Safe harbor fix" --description "Update DGCL 144 flow" --json
  exoforge-council-review --panels Governance,Security "Constitutional amendment proposal"`);
        process.exit(0);
      default:
        // Treat non-flag arguments as proposal text
        if (!argv[i].startsWith('--')) {
          if (!args.title) {
            args.title = argv[i];
            if (!args.description) args.description = argv[i];
          } else if (!args.description) {
            args.description = argv[i];
          }
        }
    }
  }

  return args;
}

/**
 * Read proposal text from stdin.
 */
async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data.trim()));
    // If no data arrives in 100ms, resolve with empty
    setTimeout(() => {
      if (data === '') resolve('');
    }, 100);
  });
}

// ── Output formatting ───────────────────────────────────────────────────────

function formatTextReport(proposal, assessments, tally) {
  const lines = [];
  lines.push('');
  lines.push('  ExoForge Council Review');
  lines.push(`  ${'='.repeat(50)}`);
  lines.push(`  Proposal: ${proposal.title}`);
  if (proposal.type) lines.push(`  Type: ${proposal.type}`);
  lines.push('');

  // Panel assessments
  for (const a of assessments) {
    const voteIcon = a.vote === 'approve' ? '[APPROVE]'
      : a.vote === 'approve_with_conditions' ? '[COND.  ]'
      : '[REJECT ]';

    lines.push(`  --- ${a.panel} Panel (${a.branch}) ---`);
    lines.push(`  Vote: ${voteIcon}  Weight: ${a.weight}  Confidence: ${a.confidence}`);

    if (a.findings.length > 0) {
      lines.push('  Findings:');
      for (const f of a.findings) {
        lines.push(`    - ${f}`);
      }
    }

    if (a.criteria_met.length > 0) {
      lines.push('  Criteria met:');
      for (const c of a.criteria_met) {
        lines.push(`    + ${c}`);
      }
    }

    if (a.criteria_failed.length > 0) {
      lines.push('  Criteria failed:');
      for (const c of a.criteria_failed) {
        lines.push(`    x ${c}`);
      }
    }
    lines.push('');
  }

  // Verdict
  lines.push(`  ${'='.repeat(50)}`);
  lines.push(`  VERDICT: ${tally.verdict}`);
  lines.push(`  Score: ${tally.score} (range: -1.0 to +1.0)`);
  if (tally.vetoed_by) {
    lines.push(`  VETOED BY: ${tally.vetoed_by} panel`);
  }
  lines.push(`  Total findings: ${tally.total_findings}`);
  lines.push(`  Panels reviewed: ${tally.panels_reviewed}`);
  lines.push('');

  // Breakdown table
  lines.push('  Vote Breakdown:');
  lines.push('  Panel         Vote                 Weight  Conf.  Weighted');
  lines.push(`  ${'─'.repeat(65)}`);
  for (const b of tally.breakdown) {
    const panelPad = b.panel.padEnd(14);
    const votePad = b.vote.padEnd(21);
    lines.push(`  ${panelPad} ${votePad} ${String(b.weight).padEnd(7)} ${String(b.confidence).padEnd(6)} ${b.weighted_value}`);
  }
  lines.push('');

  return lines.join('\n');
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  // Read from stdin if requested
  if (args.stdin) {
    const stdinText = await readStdin();
    if (stdinText) {
      if (!args.title) args.title = stdinText.split('\n')[0].substring(0, 80);
      if (!args.description) args.description = stdinText;
    }
  }

  if (!args.title && !args.description) {
    console.error('Error: provide a proposal as argument, --title/--description, or via --stdin');
    process.exit(1);
  }

  const proposal = {
    title: args.title || 'Untitled Proposal',
    description: args.description || args.title,
    type: args.type,
    affectedSystems: args.affectedSystems,
    author: args.author
  };

  // Get panels (optionally filtered)
  let panels = getPanels();
  if (args.panels) {
    const selectedNames = args.panels.map(n => n.toLowerCase());
    panels = panels.filter(p => selectedNames.includes(p.name.toLowerCase()));
    if (panels.length === 0) {
      console.error(`Error: no matching panels found. Available: ${getPanels().map(p => p.name).join(', ')}`);
      process.exit(1);
    }
  }

  // Conduct review
  const assessments = conductReview(panels, proposal);
  const tally = tallyVotes(assessments);

  if (args.json) {
    console.log(JSON.stringify({
      proposal: {
        title: proposal.title,
        type: proposal.type,
        author: proposal.author,
        affected_systems: proposal.affectedSystems
      },
      assessments,
      verdict: tally
    }, null, 2));
  } else {
    console.log(formatTextReport(proposal, assessments, tally));
  }

  // Exit code based on verdict
  const exitCode = tally.verdict === 'REJECTED' ? 1 : 0;
  process.exit(exitCode);
}

main();
