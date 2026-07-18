#!/usr/bin/env node
/**
 * Lightweight ExoForge-style triage for IntelWar work items.
 * Classifies text against the 8 IntelWar invariants + EXOCHAIN panels.
 *
 * Usage: node intelwar/tools/triage.js "title and body text..."
 */

const PANELS = {
  Governance: ["governance", "constitution", "invariant", "quorum", "doctrine", "debate"],
  Legal: ["legal", "bailment", "consent", "fiduciary", "license"],
  Architecture: ["architecture", "dag", "wasm", "crate", "adapter", "schema"],
  Security: ["security", "provenance", "signature", "sybil", "override", "secret"],
  Operations: ["deploy", "railway", "ci", "rollback", "observability", "handoff"],
};

const INVARIANTS = [
  ["living-log-integrity", ["log", "append", "dag", "hash", "rewrite"]],
  ["consent-before-memory", ["consent", "bailment", "memory"]],
  ["authority-bound-append", ["authority", "delegation", "permission"]],
  ["multi-intelligence-transparent", ["voice", "synthetic", "agent", "attestation", "ai"]],
  ["human-override-sacred", ["override", "human", "emergency"]],
  ["crosscheck-before-commit", ["crosscheck", "cross-check", ".ai"]],
  ["debate-before-doctrine", ["debate", "doctrine", "amendment"]],
  ["provenance-compounding", ["receipt", "provenance", "proof"]],
];

function scoreKeywords(text, keywords) {
  return keywords.reduce((n, k) => (text.includes(k) ? n + 1 : n), 0);
}

function triage(raw) {
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

  return {
    schema: "intelwar.triage.v1",
    panels: panels.length ? panels : [{ panel: "Architecture", score: 0 }],
    invariants: invariants.length ? invariants : [{ id: "living-log-integrity", score: 0 }],
    constitution_ref: "INTELWAR_CONSTITUTION.md",
    next: "Emit a LogEntry via tools/emit-log-entry.js and update CURSOR_AGENT_HANDOFF.md backlog.",
  };
}

const input = process.argv.slice(2).join(" ") || "";
if (!input.trim()) {
  console.error("Usage: node intelwar/tools/triage.js \"issue text\"");
  process.exit(2);
}
console.log(JSON.stringify(triage(input), null, 2));
