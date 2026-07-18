/**
 * IntelWar Living Log API — adjacent prototype.
 *
 * Does NOT claim CGR enforcement by proximity. Entries minted here are marked
 * `simulated: true` unless `INTELWAR_CORE_PROOF=1` and a verified adapter path
 * is configured. Constitutional append lives in `intelwar-core` (Rust).
 */

import cors from "cors";
import express from "express";
import { randomUUID } from "node:crypto";

const PORT = Number(process.env.PORT || 8787);
const app = express();

/** @type {Array<Record<string, unknown>>} */
const logEntries = [
  {
    entry_id: "bootstrap-001",
    entry_kind: "DevelopmentDecision",
    summary: "Adopt Living Log + 8 IntelWar Invariants on EXOCHAIN v0.2.3",
    author_did: "did:exo:intelwar-human-1",
    voice_kind: "human",
    consent_scope: "log:append",
    hlc_timestamp: { physical_ms: 1752854400000, logical: 0 },
    content_hash: "genesis-placeholder-not-cbor",
    simulated: true,
    constitution_ref: "INTELWAR_CONSTITUTION.md",
  },
];

/** @type {{ active: boolean, scope: string, bailor: string, bailee: string }} */
let consent = {
  active: false,
  scope: "log:append",
  bailor: "did:exo:intelwar-bailor",
  bailee: "did:exo:intelwar-demo-actor",
};

app.use(cors());
app.use(express.json({ limit: "64kb" }));

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    surface: "intelwar-log-api",
    trust_claim: "none",
    note: "Adjacent shell. Use cargo test -p intelwar-core for Kernel-gated append.",
  });
});

app.get("/api/log", (_req, res) => {
  res.json({
    schema_version: 1,
    simulated: true,
    entries: logEntries,
  });
});

app.get("/api/consent", (_req, res) => {
  res.json(consent);
});

app.post("/api/consent/grant", (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  consent = {
    active: true,
    scope: typeof body.scope === "string" ? body.scope : "log:append",
    bailor: typeof body.bailor === "string" ? body.bailor : consent.bailor,
    bailee: typeof body.bailee === "string" ? body.bailee : consent.bailee,
  };
  res.json({ ok: true, consent, note: "Demo consent only — not exo-consent bailment." });
});

app.post("/api/consent/revoke", (_req, res) => {
  consent = { ...consent, active: false };
  res.json({ ok: true, consent });
});

app.post("/api/log/append", (req, res) => {
  if (!consent.active) {
    return res.status(403).json({
      ok: false,
      error: "consent_required",
      message: "Grant demo consent before append (IW-1 ConsentRequired).",
    });
  }

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const summary =
    typeof body.summary === "string" && body.summary.trim()
      ? body.summary.trim()
      : "Untitled Living Log note";
  const voiceKind =
    typeof body.voice_kind === "string" ? body.voice_kind : "human";
  const agentAttestation =
    voiceKind === "synthetic"
      ? {
          model_id: body.model_id || "unspecified",
          session_id: body.session_id || "unspecified",
          tool: body.tool || "cursor-agent",
          note: "Adjacent attestation placeholder — wire AVC in core path",
        }
      : undefined;

  if (voiceKind === "synthetic" && !agentAttestation) {
    return res.status(400).json({
      ok: false,
      error: "multi_intelligence_transparent",
      message: "Synthetic voice requires agent attestation (IW-3).",
    });
  }

  const entry = {
    entry_id: randomUUID(),
    entry_kind:
      typeof body.entry_kind === "string" ? body.entry_kind : "Observation",
    summary,
    author_did:
      typeof body.author_did === "string" ? body.author_did : consent.bailee,
    voice_kind: voiceKind,
    independence: voiceKind === "human" ? "independent" : undefined,
    review_order: voiceKind === "human" ? "first_order" : undefined,
    agent_attestation: agentAttestation,
    consent_scope: consent.scope,
    hlc_timestamp: {
      physical_ms: Date.now(),
      logical: logEntries.length,
    },
    content_hash: `sim-${randomUUID()}`,
    simulated: true,
    constitution_ref: "INTELWAR_CONSTITUTION.md",
  };

  logEntries.push(entry);
  return res.status(201).json({
    ok: true,
    entry,
    warning:
      "simulated:true — not Kernel-adjudicated. Run intelwar-core append_flow for constitutional path.",
  });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`intelwar log-api listening on :${PORT}`);
});
