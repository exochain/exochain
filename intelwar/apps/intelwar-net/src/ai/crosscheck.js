/**
 * .ai crosscheck client — sign via API demo key, verify via core bin.
 */

/**
 * @param {object} draft
 */
export function draftCrossCheck(draft) {
  if (!draft?.checker_did || !draft?.subject_entry_hash_hex) {
    return {
      ok: false,
      error: "crosscheck_incomplete",
      message: "checker_did and subject_entry_hash_hex are required",
    };
  }
  if (
    draft.signature_hex &&
    (draft.signature_hex === "ab".repeat(64) ||
      draft.signature_hex.length !== 128)
  ) {
    return {
      ok: false,
      error: "fake_signature_rejected",
      message: "Refuse placeholder or malformed signature_hex",
    };
  }
  const verdict = draft.verdict || "abstain";
  const voice = draft.voice_kind || "synthetic";
  return {
    ok: true,
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
      : "Unsigned — call signDemoCrossCheck first",
  };
}

/**
 * @param {string} apiBase
 * @param {object} draft
 */
export async function signDemoCrossCheck(apiBase, draft) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) {
    return {
      ok: false,
      error: "log_api_unconfigured",
      message: "Set VITE_LOG_API_URL",
    };
  }
  const res = await fetch(`${base}/api/crosscheck/sign-demo`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      subject_entry_hash_hex: draft.subject_entry_hash_hex,
      verdict: draft.verdict || "abstain",
      evidence_hash_hex: draft.evidence_hash_hex || draft.subject_entry_hash_hex,
      voice_kind: draft.voice_kind || "synthetic",
    }),
  });
  const body = await res.json().catch(() => ({}));
  return { ...body, http_status: res.status };
}

/**
 * @param {string} apiBase
 * @param {object} payload
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
