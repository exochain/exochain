/**
 * Operator token for the guarded write surface (log-api INTELWAR_ADMIN_TOKEN).
 * Session-only storage; never persisted to localStorage or sent to any host
 * other than the configured log-api base.
 */

const KEY = "intelwar_operator_token";
let memoryToken = null;

export function getOperatorToken() {
  if (memoryToken) return memoryToken;
  try {
    if (typeof sessionStorage !== "undefined") {
      const t = sessionStorage.getItem(KEY);
      if (t) {
        memoryToken = t;
        return t;
      }
    }
  } catch {
    /* fall through */
  }
  return "";
}

/**
 * @param {string} token — empty string clears
 */
export function setOperatorToken(token) {
  const t = String(token || "").trim();
  memoryToken = t || null;
  try {
    if (typeof sessionStorage !== "undefined") {
      if (t) sessionStorage.setItem(KEY, t);
      else sessionStorage.removeItem(KEY);
    }
  } catch {
    /* memory copy remains */
  }
}

/** Headers to attach on trust-mutating requests. */
export function operatorHeaders() {
  const t = getOperatorToken();
  return t ? { authorization: `Bearer ${t}` } : {};
}

/**
 * Human-readable hint for guard failures.
 * @param {{ error?: string, message?: string }} body
 * @param {number} [status]
 */
export function writeGuardHint(body, status) {
  if (body?.error === "operator_token_required" || status === 401) {
    return "Write surface is locked — paste the operator token (Railway: INTELWAR_ADMIN_TOKEN) above, then retry.";
  }
  if (body?.error === "write_guard_unconfigured") {
    return "Write surface locked server-side: set INTELWAR_ADMIN_TOKEN on log-api.";
  }
  if (body?.error === "rate_limited") {
    return "Rate limit reached — wait a moment and retry.";
  }
  return body?.message || body?.error || "request failed";
}
