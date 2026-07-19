/**
 * IntelWar Living Log API — Kernel-required (no simulated success path).
 *
 * Requires INTELWAR_CORE_BIN + INTELWAR_CROSSCHECK_BIN or fail-closed 503.
 */

import cors from "cors";
import express from "express";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { once } from "node:events";
import path from "node:path";
import {
  invokeCoreCrosscheckSign,
  invokeCoreCrosscheckVerify,
  structuralCrosscheckCheck,
} from "./crosscheck-verify.js";
import {
  loadDagDbConfig,
  persistBridgeEntryToGateway,
} from "./dagdb-persist.js";

const PORT = Number(process.env.PORT || 8787);
const CORE_BIN = String(process.env.INTELWAR_CORE_BIN || "").trim();
const CROSSCHECK_BIN = String(process.env.INTELWAR_CROSSCHECK_BIN || "").trim();
const CROSSCHECK_SIGN_BIN = String(
  process.env.INTELWAR_CROSSCHECK_SIGN_BIN || "",
).trim();
const CORE_STATE_DIR =
  process.env.INTELWAR_CORE_STATE_DIR || ".intelwar-bridge-state";
const ACTOR_DID = "did:exo:intelwar-actor";
const BAILOR_DID = "did:exo:intelwar-bailor";

const app = express();

function dagDbConfigured() {
  try {
    return Boolean(loadDagDbConfig());
  } catch {
    return Boolean(String(process.env.INTELWAR_DAGDB_GATEWAY_URL || "").trim());
  }
}

function trustClaim() {
  if (!CORE_BIN || !CROSSCHECK_BIN) return "none";
  if (dagDbConfigured()) return "kernel_local_and_dagdb_env";
  return "kernel_local";
}

/** @returns {Array<Record<string, unknown>>} */
function loadMirrorEntries() {
  const statePath = path.join(CORE_STATE_DIR, "bridge_state.json");
  if (!existsSync(statePath)) return [];
  try {
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    return Array.isArray(state.log_mirror) ? state.log_mirror : [];
  } catch {
    return [];
  }
}

/** @type {{ active: boolean, scope: string, bailor: string, bailee: string }} */
let consent = {
  active: false,
  scope: "log:append",
  bailor: BAILOR_DID,
  bailee: ACTOR_DID,
};

app.use(cors());
app.use(express.json({ limit: "64kb" }));

app.get("/health", (_req, res) => {
  const ready = Boolean(CORE_BIN && CROSSCHECK_BIN);
  res.status(ready ? 200 : 503).json({
    status: ready ? "ok" : "kernel_required",
    surface: "intelwar-log-api",
    trust_claim: trustClaim(),
    kernel_bridge_configured: Boolean(CORE_BIN),
    crosscheck_verify_configured: Boolean(CROSSCHECK_BIN),
    crosscheck_sign_configured: Boolean(CROSSCHECK_SIGN_BIN),
    dagdb_persist_configured: dagDbConfigured(),
    durable_default: dagDbConfigured() ? "dagdb" : "local_kernel",
    note: ready
      ? "Kernel + CrossCheck bins required — append/verify fail closed."
      : "Set INTELWAR_CORE_BIN and INTELWAR_CROSSCHECK_BIN (kernel_required).",
  });
});

app.post("/api/crosscheck/sign", async (req, res) => {
  if (!CROSSCHECK_SIGN_BIN) {
    return res.status(503).json({
      ok: false,
      error: "crosscheck_sign_bin_required",
      fail_closed: true,
      message: "Set INTELWAR_CROSSCHECK_SIGN_BIN to intelwar-crosscheck-sign",
    });
  }
  const body = req.body && typeof req.body === "object" ? req.body : {};
  try {
    const signed = await invokeCoreCrosscheckSign(body, CROSSCHECK_SIGN_BIN);
    return res.status(200).json(signed);
  } catch (err) {
    return res.status(503).json({
      ok: false,
      error: err.code || "crosscheck_sign_failed",
      message: err.message || "sign failed",
      fail_closed: true,
    });
  }
});

/** Sign with server-held demo checker key (never accept client secret_key_hex). */
app.post("/api/crosscheck/sign-demo", async (req, res) => {
  if (!CROSSCHECK_SIGN_BIN) {
    return res.status(503).json({
      ok: false,
      error: "crosscheck_sign_bin_required",
      fail_closed: true,
    });
  }
  const sk = String(process.env.INTELWAR_DEMO_CHECKER_SK_HEX || "").trim();
  const checkerDid = String(
    process.env.INTELWAR_DEMO_CHECKER_DID || "did:exo:crosscheck-peer",
  ).trim();
  if (sk.length !== 64) {
    return res.status(503).json({
      ok: false,
      error: "demo_checker_key_required",
      fail_closed: true,
      message:
        "Set INTELWAR_DEMO_CHECKER_SK_HEX (64 hex chars) for UI CrossCheck signing",
    });
  }
  const body = req.body && typeof req.body === "object" ? req.body : {};
  try {
    const signed = await invokeCoreCrosscheckSign(
      {
        checker_did: checkerDid,
        subject_entry_hash_hex: body.subject_entry_hash_hex,
        verdict: body.verdict || "abstain",
        evidence_hash_hex:
          body.evidence_hash_hex || body.subject_entry_hash_hex,
        voice_kind: body.voice_kind || "synthetic",
        secret_key_hex: sk,
      },
      CROSSCHECK_SIGN_BIN,
    );
    return res.status(200).json(signed);
  } catch (err) {
    return res.status(503).json({
      ok: false,
      error: err.code || "crosscheck_sign_failed",
      message: err.message || "sign failed",
      fail_closed: true,
    });
  }
});

app.post("/api/crosscheck/verify", async (req, res) => {
  if (!CROSSCHECK_BIN) {
    return res.status(503).json({
      ok: false,
      error: "crosscheck_bin_required",
      fail_closed: true,
      message: "Set INTELWAR_CROSSCHECK_BIN (no structural-only success).",
    });
  }
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const structural = structuralCrosscheckCheck(body);
  if (!structural.ok) {
    return res.status(400).json({ ...structural, fail_closed: true });
  }
  try {
    const verified = await invokeCoreCrosscheckVerify(body, CROSSCHECK_BIN);
    return res.status(200).json(verified);
  } catch (err) {
    return res.status(503).json({
      ok: false,
      error: err.code || "crosscheck_verify_failed",
      message: err.message || "crosscheck verify failed",
      fail_closed: true,
    });
  }
});

app.get("/api/log", (_req, res) => {
  const entries = loadMirrorEntries();
  res.json({
    schema_version: 2,
    simulated: false,
    kernel_bridge_configured: Boolean(CORE_BIN),
    durable_default: dagDbConfigured() ? "dagdb" : "local_kernel",
    entries,
  });
});

app.get("/api/consent", (_req, res) => {
  res.json({
    ...consent,
    note: "Gatekeeper-compatible consent wire for Kernel bridge (not Node demo).",
  });
});

app.post("/api/consent/grant", (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  consent = {
    active: true,
    scope: typeof body.scope === "string" ? body.scope : "log:append",
    bailor: typeof body.bailor === "string" ? body.bailor : BAILOR_DID,
    bailee: typeof body.bailee === "string" ? body.bailee : ACTOR_DID,
  };
  res.json({
    ok: true,
    consent,
    note: "Active consent stored for Kernel bridge stdin wire.",
  });
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
  if (!CORE_BIN) {
    const err = new Error("INTELWAR_CORE_BIN required (kernel_required)");
    err.code = "core_bin_required";
    throw err;
  }
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
  if (parsed.simulated === true) {
    const err = new Error("kernel bridge returned simulated:true — forbidden");
    err.code = "simulated_success_forbidden";
    throw err;
  }
  return parsed;
}

app.post("/api/log/append", async (req, res) => {
  if (!CORE_BIN) {
    return res.status(503).json({
      ok: false,
      error: "core_bin_required",
      fail_closed: true,
      message: "INTELWAR_CORE_BIN required — simulated append removed.",
    });
  }
  if (!CROSSCHECK_BIN) {
    return res.status(503).json({
      ok: false,
      error: "crosscheck_bin_required",
      fail_closed: true,
      message: "INTELWAR_CROSSCHECK_BIN required alongside Kernel append.",
    });
  }
  if (!consent.active) {
    return res.status(403).json({
      ok: false,
      error: "consent_required",
      message: "Grant Active consent before append (IW-1).",
    });
  }

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const summary =
    typeof body.summary === "string" && body.summary.trim()
      ? body.summary.trim()
      : "Untitled Living Log note";
  const voiceKind =
    typeof body.voice_kind === "string" ? body.voice_kind : "human";

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
      consent: {
        active: consent.active,
        bailor_did: consent.bailor,
        bailee_did: consent.bailee,
        scope: consent.scope,
      },
    });

    let gatewayPersist;
    let durable = "local_kernel";
    try {
      gatewayPersist = await persistBridgeEntryToGateway(bridge);
      if (gatewayPersist?.attempted && gatewayPersist?.ok) {
        durable = "dagdb";
      }
    } catch (persistErr) {
      return res.status(503).json({
        ok: false,
        error: persistErr.code || "dagdb_persist_failed",
        message: persistErr.message || "DAG DB persist failed",
        fail_closed: true,
        durable: "local_kernel_not_acked",
        note: "INTELWAR_DAGDB_* configured — refusing durable claim without gateway write.",
        bridge,
      });
    }

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
      durable,
      dag_scope: bridge.dag_scope,
      gateway_persisted: Boolean(gatewayPersist?.attempted),
      constitution_ref: "INTELWAR_CONSTITUTION.md",
    };
    return res.status(201).json({
      ok: true,
      entry,
      bridge,
      gateway_persist: gatewayPersist,
    });
  } catch (err) {
    return res.status(503).json({
      ok: false,
      error: err.code || "kernel_bridge_failed",
      message: err.message || "Kernel bridge failed",
      fail_closed: true,
    });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      event: "intelwar_log_api_listen",
      port: PORT,
      trust_claim: trustClaim(),
      kernel_bridge_configured: Boolean(CORE_BIN),
      crosscheck_verify_configured: Boolean(CROSSCHECK_BIN),
      dagdb_persist_configured: dagDbConfigured(),
      node_env: process.env.NODE_ENV || "development",
    }),
  );
});
