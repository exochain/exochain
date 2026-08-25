/**
 * Write-surface guard for the IntelWar log-api.
 *
 * Interim hardening (QUALITY_MATRIX P-26/P-19): the public API previously
 * accepted anonymous consent grants, Log appends, seeds, and OpenRouter
 * spend. Until full service-scoped auth (P-10) ships:
 *  - trust-mutating routes require the operator token (fail closed when the
 *    token is unconfigured — never silently open);
 *  - browser origins are allowlisted;
 *  - per-IP rate buckets bound write and adversarial traffic;
 *  - a per-IP daily micro-USD budget bounds anonymous frontier spend.
 */

import { timingSafeEqual } from "node:crypto";

/**
 * Constant-time token comparison.
 * @param {string} provided
 * @param {string} expected
 */
export function tokenMatches(provided, expected) {
  const a = Buffer.from(String(provided || ""), "utf8");
  const b = Buffer.from(String(expected || ""), "utf8");
  if (a.length === 0 || b.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Extract an operator token from Authorization: Bearer or x-intelwar-admin.
 * @param {{ headers: Record<string, unknown> }} req
 */
export function extractOperatorToken(req) {
  const auth = String(req.headers?.authorization || "");
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return String(req.headers?.["x-intelwar-admin"] || "").trim();
}

/** Browser origins allowed to call the API (CORS). Non-browser clients have no Origin. */
export const ALLOWED_ORIGINS = new Set([
  "https://intelwar.org",
  "https://www.intelwar.org",
  "https://intelwar.press",
  "https://www.intelwar.press",
  "https://intelwar.net",
  "https://www.intelwar.net",
  "https://intelwar.ai",
  "https://www.intelwar.ai",
  "https://intelwar.tv",
  "https://www.intelwar.tv",
  "https://intelwar-net-production.up.railway.app",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:4173",
  "http://127.0.0.1:4173",
]);

/**
 * @param {string | undefined} origin
 */
export function originAllowed(origin) {
  if (!origin) return true; // curl / server-to-server: CORS does not apply
  return ALLOWED_ORIGINS.has(origin);
}

/** Fixed-window per-key rate bucket (single-replica v1). */
export class RateBucket {
  /**
   * @param {{ limit: number, windowMs: number, maxKeys?: number }} opts
   */
  constructor({ limit, windowMs, maxKeys = 5_000 }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this.buckets = new Map();
  }

  /**
   * @param {string} key
   * @param {number} nowMs
   * @returns {{ allowed: boolean, retry_after_ms: number }}
   */
  allow(key, nowMs) {
    let b = this.buckets.get(key);
    if (!b || nowMs >= b.resetAt) {
      if (!b && this.buckets.size >= this.maxKeys) {
        const oldest = this.buckets.keys().next().value;
        this.buckets.delete(oldest);
      }
      b = { count: 0, resetAt: nowMs + this.windowMs };
      this.buckets.set(key, b);
    }
    if (b.count >= this.limit) {
      return { allowed: false, retry_after_ms: Math.max(0, b.resetAt - nowMs) };
    }
    b.count += 1;
    return { allowed: true, retry_after_ms: 0 };
  }
}

/** Per-key daily integer micro-USD budget. */
export class DailyBudget {
  /**
   * @param {{ capMicroUsd: number, maxKeys?: number }} opts
   */
  constructor({ capMicroUsd, maxKeys = 5_000 }) {
    this.capMicroUsd = capMicroUsd;
    this.maxKeys = maxKeys;
    /** @type {Map<string, { dayKey: string, spent: number }>} */
    this.spendByKey = new Map();
  }

  /**
   * @param {string} key
   * @param {string} dayKey — e.g. "2026-07-20"
   */
  remaining(key, dayKey) {
    const rec = this.spendByKey.get(key);
    if (!rec || rec.dayKey !== dayKey) return this.capMicroUsd;
    return Math.max(0, this.capMicroUsd - rec.spent);
  }

  /**
   * @param {string} key
   * @param {string} dayKey
   * @param {number} microUsd
   */
  add(key, dayKey, microUsd) {
    let rec = this.spendByKey.get(key);
    if (!rec || rec.dayKey !== dayKey) {
      if (!rec && this.spendByKey.size >= this.maxKeys) {
        const oldest = this.spendByKey.keys().next().value;
        this.spendByKey.delete(oldest);
      }
      rec = { dayKey, spent: 0 };
      this.spendByKey.set(key, rec);
    }
    rec.spent += Math.max(0, Math.floor(microUsd));
  }
}
