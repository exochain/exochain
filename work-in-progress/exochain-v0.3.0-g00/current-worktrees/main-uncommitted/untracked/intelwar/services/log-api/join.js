/**
 * Join / Frontier Pass — Stripe Checkout wiring for intelwar.ai.
 *
 * Non-extractive charter: reading, Log visibility, and rate-limited
 * baseline access stay free. The pass buys frontier session volume (a
 * higher per-IP daily budget), nothing else. Fee math is integer cents
 * and shown transparently — no dark patterns.
 *
 * Fail-closed: without STRIPE_SECRET_KEY every join route returns 503.
 * Claims are verified server-side against Stripe (payment_status=paid);
 * pass tokens are stored as SHA-256 hashes on the state volume.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

/** $3.69 — 3·6·9. */
export const JOIN_PRICE_CENTS = 369;
export const PASS_VALID_DAYS = 30;
export const PASS_BUDGET_MULTIPLIER = 5;

const STRIPE_API = "https://api.stripe.com/v1";

export function stripeConfigured() {
  return Boolean(String(process.env.STRIPE_SECRET_KEY || "").trim());
}

/**
 * Stripe US card pricing estimate: 2.9% + 30¢, integer-cent math.
 * @param {number} amountCents
 */
export function feeBreakdownCents(amountCents) {
  const amount = Math.max(0, Math.floor(amountCents));
  const percentFee = Math.ceil((amount * 29) / 1000);
  const fee = percentFee + 30;
  return {
    amount_cents: amount,
    stripe_fee_cents: fee,
    net_cents: Math.max(0, amount - fee),
    basis: "US card 2.9% + 30¢ — international/AMEX can add ~1.5%",
  };
}

/**
 * Gross charge needed to net a target after US-card fees.
 * @param {number} netCents
 */
export function grossForNetCents(netCents) {
  const net = Math.max(0, Math.floor(netCents));
  return Math.ceil(((net + 30) * 1000) / 971);
}

/**
 * @param {{ successUrl: string, cancelUrl: string }} p
 */
export async function createCheckoutSession({ successUrl, cancelUrl }) {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  if (!key) {
    const err = new Error("STRIPE_SECRET_KEY required");
    err.code = "stripe_unconfigured";
    throw err;
  }
  const form = new URLSearchParams({
    mode: "payment",
    "line_items[0][price_data][currency]": "usd",
    "line_items[0][price_data][product_data][name]":
      "IntelWar Frontier Pass (30 days)",
    "line_items[0][price_data][product_data][description]":
      "Raises your daily frontier adversarial budget 5x. Reads stay free for everyone.",
    "line_items[0][price_data][unit_amount]": String(JOIN_PRICE_CENTS),
    "line_items[0][quantity]": "1",
    "metadata[product]": "frontier-pass",
    success_url: successUrl,
    cancel_url: cancelUrl,
  });
  const res = await fetch(`${STRIPE_API}/checkout/sessions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body?.error?.message || `Stripe HTTP ${res.status}`);
    err.code = "stripe_http_error";
    err.status = res.status;
    throw err;
  }
  return { id: body.id, url: body.url };
}

/**
 * @param {string} sessionId
 */
export async function fetchCheckoutSession(sessionId) {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  if (!key) {
    const err = new Error("STRIPE_SECRET_KEY required");
    err.code = "stripe_unconfigured";
    throw err;
  }
  const res = await fetch(
    `${STRIPE_API}/checkout/sessions/${encodeURIComponent(sessionId)}`,
    { headers: { Authorization: `Bearer ${key}` } },
  );
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body?.error?.message || `Stripe HTTP ${res.status}`);
    err.code = "stripe_http_error";
    err.status = res.status;
    throw err;
  }
  return body;
}

/* ---------- pass store (volume-backed) ---------- */

function passStorePath(stateDir) {
  return path.join(stateDir, "frontier_passes.json");
}

/**
 * @param {string} stateDir
 * @returns {{ passes: Record<string, any>, claimed_sessions: Record<string, string> }}
 */
export function loadPassStore(stateDir) {
  const p = passStorePath(stateDir);
  if (!existsSync(p)) return { passes: {}, claimed_sessions: {} };
  try {
    const raw = JSON.parse(readFileSync(p, "utf8"));
    return {
      passes: raw.passes && typeof raw.passes === "object" ? raw.passes : {},
      claimed_sessions:
        raw.claimed_sessions && typeof raw.claimed_sessions === "object"
          ? raw.claimed_sessions
          : {},
    };
  } catch {
    return { passes: {}, claimed_sessions: {} };
  }
}

function savePassStore(stateDir, store) {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(passStorePath(stateDir), JSON.stringify(store, null, 2));
}

function hashToken(token) {
  return createHash("sha256").update(String(token), "utf8").digest("hex");
}

/**
 * Issue a pass for a verified-paid Stripe session. Double-claim safe.
 * @param {string} stateDir
 * @param {{ sessionId: string, amountCents: number, nowMs: number }} p
 * @returns {{ ok: true, pass_token: string, expires_at_ms: number } | { ok: false, error: string }}
 */
export function issuePass(stateDir, { sessionId, amountCents, nowMs }) {
  const store = loadPassStore(stateDir);
  if (store.claimed_sessions[sessionId]) {
    return { ok: false, error: "session_already_claimed" };
  }
  const token = `fp_${randomBytes(24).toString("hex")}`;
  const expiresAtMs = nowMs + PASS_VALID_DAYS * 24 * 60 * 60 * 1000;
  store.passes[hashToken(token)] = {
    stripe_session: sessionId,
    amount_cents: Math.floor(amountCents),
    issued_at_ms: nowMs,
    expires_at_ms: expiresAtMs,
  };
  store.claimed_sessions[sessionId] = hashToken(token);
  savePassStore(stateDir, store);
  return { ok: true, pass_token: token, expires_at_ms: expiresAtMs };
}

/**
 * @param {string} stateDir
 * @param {string} token
 * @param {number} nowMs
 * @returns {{ valid: boolean, expires_at_ms?: number }}
 */
export function passValid(stateDir, token, nowMs) {
  if (!token) return { valid: false };
  const store = loadPassStore(stateDir);
  const rec = store.passes[hashToken(token)];
  if (!rec) return { valid: false };
  if (nowMs >= rec.expires_at_ms) return { valid: false };
  return { valid: true, expires_at_ms: rec.expires_at_ms };
}

/**
 * @param {string} stateDir
 */
export function passCount(stateDir) {
  return Object.keys(loadPassStore(stateDir).passes).length;
}
