/**
 * CrossCheck verification — Kernel-required (no structural-only success).
 */

import { spawn } from "node:child_process";
import { once } from "node:events";

const VERDICTS = new Set(["agree", "disagree", "abstain"]);
const VOICES = new Set(["human", "synthetic", "system"]);

/**
 * Shape check only — never returns ok:true as a success path for the API.
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
  const keys = body.trusted_checker_keys_hex;
  if (!authorDid || !subject || !crosschecks || crosschecks.length === 0) {
    return {
      ok: false,
      error: "crosscheck_incomplete",
      message:
        "author_did, subject_entry_hash_hex, and non-empty crosschecks are required",
    };
  }
  if (!keys || typeof keys !== "object") {
    return {
      ok: false,
      error: "trusted_keys_required",
      message: "trusted_checker_keys_hex is required for core verify",
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
      return { ok: false, error: "invalid_verdict", message: `index ${i}` };
    }
    if (!VOICES.has(String(row.voice_kind || ""))) {
      return { ok: false, error: "invalid_voice_kind", message: `index ${i}` };
    }
    const sigHex = String(row.signature_hex || "");
    if (sigHex.length !== 128) {
      return {
        ok: false,
        error: "invalid_signature_shape",
        message: `index ${i}: signature_hex must be 128 hex chars (real Ed25519)`,
      };
    }
  }
  return { ok: true, shape_valid: true };
}

/**
 * @param {Record<string, unknown>} body
 * @param {string} bin
 */
export async function invokeCoreCrosscheckVerify(body, bin) {
  return spawnJsonBin(bin, body, "crosscheck_verify");
}

/**
 * @param {Record<string, unknown>} body
 * @param {string} bin
 */
export async function invokeCoreCrosscheckSign(body, bin) {
  return spawnJsonBin(bin, body, "crosscheck_sign");
}

/**
 * @param {string} bin
 * @param {Record<string, unknown>} body
 * @param {string} label
 */
async function spawnJsonBin(bin, body, label) {
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
      `${label} returned non-JSON (exit ${code}): ${raw.slice(0, 400)}`,
    );
    err.code = `${label}_invalid_output`;
    throw err;
  }
  if (code !== 0 || parsed.ok !== true) {
    const err = new Error(parsed.message || `${label} failed`);
    err.code = parsed.error || `${label}_failed`;
    err.detail = parsed;
    throw err;
  }
  if (parsed.simulated === true) {
    const err = new Error(`${label} refused simulated:true success`);
    err.code = "simulated_success_forbidden";
    throw err;
  }
  return parsed;
}
