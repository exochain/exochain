#!/usr/bin/env node
/**
 * ExoForge-style triage for IntelWar work items (PM-006).
 * Classifies text against the 8 IntelWar invariants + EXOCHAIN panels,
 * and emits suggested GitHub labels (`iw:*`, `panel:*`).
 *
 * Usage:
 *   node intelwar/tools/triage.js "title and body text..."
 *   node intelwar/tools/triage.js --labels "consent bailment fail-closed"
 */

import { pathToFileURL } from "node:url";

export const PANELS = {
  Governance: ["governance", "constitution", "invariant", "quorum", "doctrine", "debate"],
  Legal: ["legal", "bailment", "consent", "fiduciary", "license"],
  Architecture: ["architecture", "dag", "wasm", "crate", "adapter", "schema"],
  Security: ["security", "provenance", "signature", "sybil", "override", "secret"],
  Operations: ["deploy", "railway", "ci", "rollback", "observability", "handoff"],
};

export const INVARIANTS = [
  ["consent-required", ["consent", "bailment", "revoke"]],
  ["provenance-verifiable", ["provenance", "receipt", "hash", "lineage", "attester"]],
  ["multi-intelligence-transparent", ["voice", "synthetic", "agent", "attestation", "ai", "avc"]],
  ["evidence-disciplined", ["evidence", "crosscheck", "assertion", "debate"]],
  ["human-override-priority", ["override", "human", "emergency", "contested"]],
  ["fail-closed-enforcement", ["fail-closed", "bypass", "unauthorized", "reject"]],
  ["strategic-utility", ["strategy", "utility", "insight", "narrative", "truth"]],
  ["log-integrity", ["log", "append", "dag", "integrity", "export"]],
];

function scoreKeywords(text, keywords) {
  return keywords.reduce((n, k) => (text.includes(k) ? n + 1 : n), 0);
}

/**
 * @param {string} raw
 */
export function triage(raw) {
  const text = String(raw || "").toLowerCase();
  const panels = Object.entries(PANELS)
    .map(([panel, keywords]) => ({ panel, score: scoreKeywords(text, keywords) }))
    .filter((p) => p.score > 0)
    .sort((a, b) => b.score - a.score);

  const invariants = INVARIANTS.map(([id, keywords]) => ({
    id,
    score: scoreKeywords(text, keywords),
  }))
    .filter((i) => i.score > 0)
    .sort((a, b) => b.score - a.score);

  const primaryPanels = panels.length ? panels : [{ panel: "Architecture", score: 0 }];
  const primaryInvariants = invariants.length
    ? invariants
    : [{ id: "log-integrity", score: 0 }];

  const labels = [
    ...primaryInvariants.slice(0, 3).map((i) => `iw:${i.id}`),
    ...primaryPanels.slice(0, 2).map((p) => `panel:${p.panel.toLowerCase()}`),
  ];

  return {
    schema: "intelwar.triage.v1",
    panels: primaryPanels,
    invariants: primaryInvariants,
    labels,
    github_label_suggestions: labels,
    constitution_ref: "INTELWAR_CONSTITUTION.md",
    next: "Apply labels; emit a LogEntry via tools/emit-log-entry.js; update CURSOR_AGENT_HANDOFF.md backlog.",
  };
}

function parseArgs(argv) {
  const args = { labelsOnly: false, text: "" };
  const parts = [];
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--labels") {
      args.labelsOnly = true;
      continue;
    }
    if (argv[i] === "--help" || argv[i] === "-h") {
      console.log(`Usage: triage.js [--labels] "issue text"

Options:
  --labels   Print suggested labels one per line
  -h, --help Show help`);
      process.exit(0);
    }
    parts.push(argv[i]);
  }
  args.text = parts.join(" ");
  return args;
}

const isMain =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const args = parseArgs(process.argv);
  if (!args.text.trim()) {
    console.error('Usage: node intelwar/tools/triage.js "issue text"');
    process.exit(2);
  }
  const result = triage(args.text);
  if (args.labelsOnly) {
    for (const label of result.labels) {
      console.log(label);
    }
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}
