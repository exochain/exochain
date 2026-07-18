#!/usr/bin/env node
/**
 * Emit a LogEntry-shaped DevelopmentDecision artifact (simulated JSON).
 * Feed into the next agent session / Living Log API.
 *
 * Usage:
 *   node intelwar/tools/emit-log-entry.js --summary "..." --kind DevelopmentDecision
 */

import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

function arg(name, fallback = "") {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx >= 0 && process.argv[idx + 1]) return process.argv[idx + 1];
  return fallback;
}

const summary = arg("summary", "Untitled development decision");
const kind = arg("kind", "DevelopmentDecision");
const voice = arg("voice", "synthetic");
const outDir = arg("out", "intelwar/docs/log-artifacts");

const entry = {
  schema_version: 1,
  entry_id: randomUUID(),
  entry_kind: kind,
  author_did: arg("author", "did:exo:cursor-agent"),
  hlc_timestamp: {
    physical_ms: Date.now(),
    logical: 0,
  },
  parent_hashes: [],
  summary,
  payload: {
    refs: ["INTELWAR_CONSTITUTION.md", "docs/CURSOR_AGENT_HANDOFF.md"],
  },
  voice_kind: voice,
  independence: voice === "human" ? "independent" : undefined,
  review_order: voice === "human" ? "first_order" : undefined,
  agent_attestation:
    voice === "synthetic"
      ? {
          model_id: arg("model", "cursor-agent"),
          session_id: arg("session", "unspecified"),
          tool: "cursor",
          attestation_signature: [],
        }
      : undefined,
  requires_crosscheck: false,
  crosscheck_refs: [],
  debate_ref: null,
  consent_scope: "log:append",
  intelwar_invariants: [
    "living-log-integrity",
    "consent-before-memory",
    "authority-bound-append",
    "multi-intelligence-transparent",
    "human-override-sacred",
    "crosscheck-before-commit",
    "debate-before-doctrine",
    "provenance-compounding",
  ],
  exochain_invariants: [
    "separation-of-powers",
    "consent-required",
    "no-self-grant",
    "human-override",
    "kernel-immutability",
    "authority-chain-valid",
    "quorum-legitimate",
    "provenance-verifiable",
  ],
  simulated: true,
  note: "Simulated artifact — promote via intelwar_core::append_log_entry for constitutional commit.",
};

mkdirSync(outDir, { recursive: true });
const file = path.join(outDir, `${entry.entry_id}.json`);
writeFileSync(file, JSON.stringify(entry, null, 2));
console.log(JSON.stringify({ ok: true, file, entry_id: entry.entry_id, summary }, null, 2));
