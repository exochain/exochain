/**
 * IntelWar Living Log API — adjacent prototype.
 *
 * Default path: `simulated: true` (honest adjacent shell).
 * Kernel path: set `INTELWAR_CORE_BIN` to `intelwar-log-append`. When configured,
 * appends fail closed on bridge errors (no silent simulated Permitted).
 */

import cors from "cors";
import express from "express";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";

const PORT = Number(process.env.PORT || 8787);
const CORE_BIN = process.env.INTELWAR_CORE_BIN || "";
const CORE_STATE_DIR =
  process.env.INTELWAR_CORE_STATE_DIR || ".intelwar-bridge-state";
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
    kernel_bridge_configured: Boolean(CORE_BIN),
    note: CORE_BIN
      ? "INTELWAR_CORE_BIN set — append uses Kernel bridge (fail closed)."
      : "Adjacent shell. Set INTELWAR_CORE_BIN to enable Kernel-gated append.",
  });
});

app.get("/api/log", (_req, res) => {
  const anySimulated = logEntries.some((e) => e.simulated !== false);
  res.json({
    schema_version: 1,
    simulated: anySimulated,
    kernel_bridge_configured: Boolean(CORE_BIN),
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

/**
 * @param {Record<string, unknown>} payload
 * @returns {Promise<Record<string, unknown>>}
 */
async function invokeKernelBridge(payload) {
  const child = spawn(CORE_BIN, [], {
    env: { ...process.env, INTELWAR_CORE_STATE_DIR: CORE_STATE_DIR },
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.write(JSON.stringify(payload));
  child.stdin.end();

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const [code] = await once(child, "close");
  const raw = stdout.trim() || stderr.trim();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    const err = new Error(
      `kernel bridge returned non-JSON (exit ${code}): ${raw.slice(0, 400)}`,
    );
    err.code = "kernel_bridge_invalid_output";
    throw err;
  }
  if (code !== 0 || parsed.ok !== true) {
    const err = new Error(parsed.message || parsed.error || "kernel append failed");
    err.code = parsed.error || "kernel_append_failed";
    err.detail = parsed;
    throw err;
  }
  return parsed;
}

app.post("/api/log/append", async (req, res) => {
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

  if (CORE_BIN) {
    try {
      const bridge = await invokeKernelBridge({
        summary,
        entry_kind:
          typeof body.entry_kind === "string" ? body.entry_kind : "Observation",
        voice_kind: voiceKind,
        model_id: body.model_id,
        session_id: body.session_id,
        tool: body.tool || "intelwar-log-api",
        payload:
          typeof body.payload === "string"
            ? body.payload
            : JSON.stringify({ via: "log-api", consent_bailee: consent.bailee }),
      });
      const entry = {
        entry_id: bridge.entry_id,
        entry_kind:
          typeof body.entry_kind === "string" ? body.entry_kind : "Observation",
        summary: bridge.summary,
        author_did: bridge.author_did,
        voice_kind: bridge.voice_kind,
        consent_scope: consent.scope,
        content_hash: bridge.content_hash,
        dag_node_hash: bridge.dag_node_hash,
        receipt_hash: bridge.receipt_hash,
        previous_receipt_hash: bridge.previous_receipt_hash,
        simulated: false,
        kernel_adjudicated: true,
        dag_scope: bridge.dag_scope,
        constitution_ref: "INTELWAR_CONSTITUTION.md",
      };
      logEntries.push(entry);
      return res.status(201).json({
        ok: true,
        entry,
        bridge,
      });
    } catch (err) {
      return res.status(503).json({
        ok: false,
        error: err.code || "kernel_bridge_failed",
        message: err.message || "Kernel bridge failed",
        fail_closed: true,
        note: "INTELWAR_CORE_BIN is set — refusing simulated fallback (IW-6).",
      });
    }
  }

  const agentAttestation =
    voiceKind === "synthetic"
      ? {
          model_id: body.model_id || "unspecified",
          session_id: body.session_id || "unspecified",
          tool: body.tool || "cursor-agent",
          note: "Adjacent attestation placeholder — set INTELWAR_CORE_BIN for Kernel path",
        }
      : undefined;

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
    kernel_adjudicated: false,
    constitution_ref: "INTELWAR_CONSTITUTION.md",
  };

  logEntries.push(entry);
  return res.status(201).json({
    ok: true,
    entry,
    warning:
      "simulated:true — set INTELWAR_CORE_BIN to intelwar-log-append for Kernel adjudication.",
  });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(
    `intelwar log-api listening on :${PORT} (kernel_bridge=${Boolean(CORE_BIN)})`,
  );
});
