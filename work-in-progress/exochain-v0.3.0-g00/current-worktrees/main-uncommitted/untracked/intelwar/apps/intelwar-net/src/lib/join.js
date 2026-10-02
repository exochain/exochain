/**
 * Join / Frontier Pass client — Stripe Checkout via log-api.
 * Pass token stored locally (30-day spend credential); attached as
 * x-intelwar-pass on adversarial runs to raise the daily budget.
 */

const PASS_KEY = "intelwar_frontier_pass";
let passMemory = null;

export function getPassToken() {
  if (passMemory) return passMemory;
  try {
    if (typeof localStorage !== "undefined") {
      const raw = localStorage.getItem(PASS_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed?.token && Date.now() < Number(parsed.expires_at_ms || 0)) {
          passMemory = parsed.token;
          return parsed.token;
        }
        localStorage.removeItem(PASS_KEY);
      }
    }
  } catch {
    /* fall through */
  }
  return "";
}

/**
 * @param {string} token
 * @param {number} expiresAtMs
 */
export function storePassToken(token, expiresAtMs) {
  passMemory = token || null;
  try {
    if (typeof localStorage !== "undefined") {
      if (token) {
        localStorage.setItem(
          PASS_KEY,
          JSON.stringify({ token, expires_at_ms: expiresAtMs }),
        );
      } else {
        localStorage.removeItem(PASS_KEY);
      }
    }
  } catch {
    /* memory copy remains */
  }
}

export function passHeaders() {
  const t = getPassToken();
  return t ? { "x-intelwar-pass": t } : {};
}

/**
 * @param {string} apiBase
 */
export async function fetchJoinEconomics(apiBase) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) return { ok: false, configured: false, error: "log_api_unconfigured" };
  try {
    const res = await fetch(`${base}/api/join/economics`);
    return { ...(await res.json()), http_status: res.status };
  } catch (err) {
    return {
      ok: false,
      configured: false,
      error: err instanceof Error ? err.message : "fetch failed",
    };
  }
}

/**
 * @param {string} apiBase
 */
export async function startJoinCheckout(apiBase) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) return { ok: false, error: "log_api_unconfigured" };
  try {
    const res = await fetch(`${base}/api/join/checkout`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        return_origin:
          typeof window !== "undefined"
            ? `${window.location.protocol}//${window.location.host}`
            : "https://intelwar.ai",
      }),
    });
    const body = await res.json().catch(() => ({}));
    return { ...body, http_status: res.status };
  } catch (err) {
    return {
      ok: false,
      error: "checkout_fetch_failed",
      message: err instanceof Error ? err.message : "failed",
    };
  }
}

/**
 * Consume ?join=success&session_id=… once; claim and store the pass.
 * @param {string} apiBase
 * @returns {Promise<{ claimed: boolean, message: string } | null>}
 */
export async function claimPassFromUrl(apiBase) {
  if (typeof window === "undefined") return null;
  const params = new URLSearchParams(window.location.search);
  const joinState = params.get("join");
  if (!joinState) return null;

  const cleanUrl = () => {
    params.delete("join");
    params.delete("session_id");
    const qs = params.toString();
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${qs ? `?${qs}` : ""}${window.location.hash}`,
    );
  };

  if (joinState !== "success") {
    cleanUrl();
    return { claimed: false, message: "Checkout cancelled — nothing charged." };
  }
  const sessionId = params.get("session_id") || "";
  cleanUrl();
  if (!sessionId) {
    return { claimed: false, message: "Missing session id on return URL." };
  }
  const base = String(apiBase || "").replace(/\/$/, "");
  try {
    const res = await fetch(
      `${base}/api/join/claim?session_id=${encodeURIComponent(sessionId)}`,
    );
    const body = await res.json().catch(() => ({}));
    if (res.ok && body.ok && body.pass_token) {
      storePassToken(body.pass_token, Number(body.expires_at_ms));
      return {
        claimed: true,
        message:
          "Frontier Pass active — daily budget raised 5x for 30 days on this browser.",
      };
    }
    if (body.error === "session_already_claimed") {
      return {
        claimed: false,
        message:
          "This payment was already claimed (possibly in another tab). If you lost the pass, contact the operator.",
      };
    }
    return {
      claimed: false,
      message: body.message || body.error || "Claim failed — payment not verified.",
    };
  } catch (err) {
    return {
      claimed: false,
      message: err instanceof Error ? err.message : "claim failed",
    };
  }
}
