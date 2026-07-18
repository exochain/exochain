/**
 * .ai crosscheck client (IW-4 / PM-004).
 *
 * Drafts CrossCheckResult-shaped payloads and verifies via log-api.
 * Core Ed25519 verification requires INTELWAR_CROSSCHECK_BIN on the API.
 */

/**
 * @typedef {{
 *   checker_did: string,
 *   subject_entry_hash_hex: string,
 *   verdict: 'agree'|'disagree'|'abstain',
 *   evidence_hash_hex: string,
 *   voice_kind: 'human'|'synthetic'|'system',
 *   signature_hex?: string,
 * }} CrossCheckDraft
 */

/**
 * Build a draft wire-format CrossCheck for core / log-api verify.
 * @param {CrossCheckDraft} draft
 */
export function draftCrossCheck(draft) {
  if (!draft?.checker_did || !draft?.subject_entry_hash_hex) {
    return {
      ok: false,
      error: "crosscheck_incomplete",
      message: "checker_did and subject_entry_hash_hex are required",
    };
  }
  const verdict = draft.verdict || "abstain";
  const voice = draft.voice_kind || "synthetic";
  return {
    ok: true,
    simulated: !draft.signature_hex,
    result: {
      checker_did: draft.checker_did,
      subject_entry_hash_hex: draft.subject_entry_hash_hex,
      verdict,
      evidence_hash_hex: draft.evidence_hash_hex || draft.subject_entry_hash_hex,
      voice_kind: voice,
      signature_hex: draft.signature_hex || "",
    },
    note: draft.signature_hex
      ? "Ready for POST /api/crosscheck/verify"
      : "Unsigned draft — core verify requires signature_hex",
  };
}

/**
 * Verify crosschecks through the adjacent log-api (PM-004).
 * @param {string} apiBase
 * @param {{
 *   author_did: string,
 *   subject_entry_hash_hex: string,
 *   crosschecks: Array<Record<string, unknown>>,
 *   trusted_checker_keys_hex?: Record<string, string[]>,
 * }} payload
 */
export async function verifyCrossCheck(apiBase, payload) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) {
    return {
      ok: false,
      error: "log_api_unconfigured",
      message: "Set VITE_LOG_API_URL for crosscheck verify",
    };
  }
  const res = await fetch(`${base}/api/crosscheck/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  return {
    ...body,
    http_status: res.status,
  };
}

/**
 * Hook for .ai layer UI — prefer verifyCrossCheck when API is available.
 * @param {string} subjectHashHex
 */
export async function requestCrossCheck(subjectHashHex) {
  if (!subjectHashHex) {
    return {
      ok: false,
      error: "ai_crosscheck_incomplete",
      message: "subject hash required",
    };
  }
  return {
    ok: false,
    error: "ai_crosscheck_needs_checker_keys",
    message:
      "Provide signed CrossCheckResult + trusted_checker_keys_hex via verifyCrossCheck (PM-004).",
    subject_entry_hash_hex: subjectHashHex,
  };
}
