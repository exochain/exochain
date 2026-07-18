/**
 * PM-004: CrossCheck verification helper for adjacent log-api.
 *
 * Without INTELWAR_CROSSCHECK_BIN: structural checks only (simulated).
 * With INTELWAR_CROSSCHECK_BIN: spawn intelwar-crosscheck-verify (fail closed).
 */

import { spawn } from "node:child_process";
import { once } from "node:events";

const VERDICTS = new Set(["agree", "disagree", "abstain"]);
const VOICES = new Set(["human", "synthetic", "system"]);

/**
 * @param {unknown} raw
 */
export function structuralCrosscheckCheck(raw) {
  if (!raw || typeof raw !== "object") {
    return { ok: false, error: "invalid_body", message: "expected object" };
  }
  const body = /** @type {Record<string, unknown>} */ (raw);
  const authorDid = String(body.author_did || "").trim();
  const subject = String(body.subject_entry_hash_hex || "").trim();
  const crosschecks = Array.isArray(body.crosschecks) ? body.crosschecks : null;
  if (!authorDid || !subject || !crosschecks || crosschecks.length === 0) {
    return {
      ok: false,
      error: "crosscheck_incomplete",
      message:
        "author_did, subject_entry_hash_hex, and non-empty crosschecks are required",
    };
  }
  for (let i = 0; i < crosschecks.length; i++) {
    const c = crosschecks[i];
    if (!c || typeof c !== "object") {
      return { ok: false, error: "invalid_crosscheck", message: `index ${i}` };
    }
    const row = /** @type {Record<string, unknown>} */ (c);
    if (String(row.checker_did || "") === authorDid) {
      return {
        ok: false,
        error: "self_crosscheck",
        message: `self-crosscheck denied at index ${i}`,
      };
    }
    if (!VERDICTS.has(String(row.verdict || ""))) {
      return {
        ok: false,
        error: "invalid_verdict",
        message: `index ${i}`,
      };
    }
    if (!VOICES.has(String(row.voice_kind || ""))) {
      return {
        ok: false,
        error: "invalid_voice_kind",
        message: `index ${i}`,
      };
    }
    const sig = row.signature;
    const sigHex = row.signature_hex;
    const sigOk =
      (Array.isArray(sig) && sig.length === 64) ||
      (typeof sig === "string" && sig.length === 128) ||
      (typeof sigHex === "string" && sigHex.length === 128);
    if (!sigOk) {
      return {
        ok: false,
        error: "invalid_signature_shape",
        message: `index ${i}: need signature[64] or signature_hex (128 hex chars)`,
      };
    }
  }
  return {
    ok: true,
    simulated: true,
    core_verified: false,
    count: crosschecks.length,
    note: "Structural check only — set INTELWAR_CROSSCHECK_BIN for Ed25519 verify",
  };
}

/**
 * @param {Record<string, unknown>} body
 * @param {string} bin
 */
export async function invokeCoreCrosscheckVerify(body, bin) {
  const child = spawn(bin, [], {
    env: { ...process.env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.write(JSON.stringify(body));
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
      `crosscheck verify returned non-JSON (exit ${code}): ${raw.slice(0, 400)}`,
    );
    err.code = "crosscheck_verify_invalid_output";
    throw err;
  }
  if (code !== 0 || parsed.ok !== true) {
    const err = new Error(parsed.message || "crosscheck verify failed");
    err.code = parsed.error || "crosscheck_verify_failed";
    err.detail = parsed;
    throw err;
  }
  return parsed;
}
