/**
 * intelwar.ai client — OpenRouter adversarial runs via log-api proxy.
 * Structured outputs; Multi-Intelligence Transparency; never final authority.
 */

/**
 * @typedef {'stress_test'|'cross_check'|'red_team'} AdversarialMode
 */

/**
 * Local structure-only dry run when OpenRouter is unavailable.
 * Explicitly NOT frontier — for UX / schema rehearsal only.
 * @param {{ mode: AdversarialMode, claim: string, focus?: string[], steelman_first?: boolean }} input
 */
export function localStructureDryRun(input) {
  const claim = String(input.claim || "").trim();
  const mode = input.mode || "stress_test";
  const focus = input.focus || [];
  const steelman = input.steelman_first !== false;

  const content = {
    strongest_interpretation: steelman
      ? `Charitable reading: the claim asserts that «${claim.slice(0, 180)}» should be treated as a load-bearing position under contest.`
      : `Direct reading of the submitted claim (steelman skipped by user).`,
    key_vulnerabilities: [
      "Scope may be underspecified — success criteria unclear.",
      focus.includes("evidence")
        ? "Evidence chain not yet bound to Living Log receipts."
        : "Hidden assumptions may do more work than stated premises.",
      "Adversary can reframe the claim to a weaker proximate target.",
    ],
    strongest_counters: [
      "A stronger opposing frame may invert the burden of proof.",
      "Without provenance-linked evidence, the claim remains contestable performance.",
    ],
    evidence_gaps: [
      "No cited receipt hashes or Log entry IDs.",
      "No explicit time-bounded predictions.",
    ],
    fortifications: [
      "State the minimal claim that would still matter if true.",
      "Attach at least one Log-bound evidence pointer before publishing.",
      "Pre-register what would count as a decisive defeat.",
    ],
    objection_quality: [
      {
        objection: "Category error between narrative force and evidentiary force",
        strength: "strong",
      },
      {
        objection: "Audience capture mistaken for truth-tracking",
        strength: "moderate",
      },
    ],
    notes:
      "STRUCTURE DEMO ONLY — not a frontier model. Set OPENROUTER_API_KEY on log-api for real runs.",
  };

  return {
    ok: true,
    mode,
    claim,
    provider: "local-structure-demo",
    voice_kind: "synthetic",
    final_authority: false,
    multi_intelligence_transparency: true,
    dry_run: true,
    models_used: ["local/structure-demo"],
    runs: [
      {
        model: "local/structure-demo",
        model_requested: "local/structure-demo",
        provider: "local-structure-demo",
        voice_kind: "synthetic",
        content,
      },
    ],
    artifact_draft: {
      entry_kind: "AdversarialAnalysis",
      summary: `${mode} (dry-run): ${claim.slice(0, 100)}`,
      voice_kind: "synthetic",
      model_ids: ["local/structure-demo"],
      provider: "local-structure-demo",
      provenance: {
        multi_intelligence: true,
        final_authority: false,
        eligible_for_log: false,
        requires_consent: true,
        dry_run: true,
      },
    },
    note: "Dry-run schema rehearsal. Not frontier. Not Log-eligible until a real OpenRouter run.",
  };
}

const SESSION_KEY = "intelwar_ai_session";
let sessionMemory = null;

/** Stable per-tab session id so server-side cost ceilings apply per session. */
export function adversarialSessionId() {
  if (sessionMemory) return sessionMemory;
  try {
    if (typeof sessionStorage !== "undefined") {
      const existing = sessionStorage.getItem(SESSION_KEY);
      if (existing) {
        sessionMemory = existing;
        return existing;
      }
      const fresh = `s-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e9).toString(36)}`;
      sessionStorage.setItem(SESSION_KEY, fresh);
      sessionMemory = fresh;
      return fresh;
    }
  } catch {
    /* fall through to memory */
  }
  sessionMemory = `s-${Date.now().toString(36)}`;
  return sessionMemory;
}

/**
 * Format integer micro-USD for display without float arithmetic.
 * @param {number} microUsd
 */
export function formatMicroUsd(microUsd) {
  const micro = Math.max(0, Math.floor(Number(microUsd) || 0));
  const dollars = Math.floor(micro / 1_000_000);
  const frac4 = String(Math.floor((micro % 1_000_000) / 100)).padStart(4, "0");
  const trimmed = frac4.length > 2 && frac4.endsWith("00")
    ? frac4.slice(0, 2)
    : frac4;
  return `$${dollars}.${trimmed}`;
}

/**
 * @param {string} apiBase
 * @param {object} input
 */
export async function runAdversarialRemote(apiBase, input) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) {
    return {
      ok: false,
      error: "log_api_unconfigured",
      message: "Set VITE_LOG_API_URL",
      fail_closed: true,
      final_authority: false,
    };
  }
  const res = await fetch(`${base}/api/adversarial/run`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  const body = await res.json().catch(() => ({}));
  return { ...body, http_status: res.status };
}

/**
 * @param {string} apiBase
 */
export async function fetchAdversarialCatalog(apiBase) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base) {
    return {
      ok: false,
      configured: false,
      models: {},
      error: "log_api_unconfigured",
    };
  }
  try {
    const res = await fetch(`${base}/api/adversarial/catalog`);
    const body = await res.json().catch(() => ({}));
    return { ...body, http_status: res.status };
  } catch (err) {
    return {
      ok: false,
      configured: false,
      error: "catalog_fetch_failed",
      message: err instanceof Error ? err.message : "failed",
    };
  }
}

/**
 * Prefer remote OpenRouter; fall back to labeled dry-run when unconfigured.
 * @param {string} apiBase
 * @param {object} input
 * @param {{ allowDryRun?: boolean }} [opts]
 */
export async function runAdversarial(apiBase, input, opts = {}) {
  const allowDryRun = opts.allowDryRun !== false;
  const wired = { session_id: adversarialSessionId(), ...input };
  const remote = await runAdversarialRemote(apiBase, wired);
  if (remote.ok) return remote;
  if (
    allowDryRun &&
    (remote.error === "openrouter_unconfigured" ||
      remote.error === "log_api_unconfigured" ||
      remote.http_status === 503)
  ) {
    return {
      ...localStructureDryRun(wired),
      remote_error: remote.error || remote.message,
      log_write: { attempted: false, ok: false, error: "dry_run" },
    };
  }
  return remote;
}

/**
 * Normalize stress-test content for UI whether frontier or dry-run.
 * @param {Record<string, unknown>} run
 */
export function normalizeStressSections(run) {
  const c = run?.content && typeof run.content === "object" ? run.content : {};
  return {
    model: run.model || "unknown",
    voice_kind: run.voice_kind || "synthetic",
    strongest_interpretation: String(c.strongest_interpretation || ""),
    key_vulnerabilities: asStringList(c.key_vulnerabilities),
    strongest_counters: asStringList(c.strongest_counters),
    evidence_gaps: asStringList(c.evidence_gaps),
    fortifications: asStringList(c.fortifications),
    objection_quality: Array.isArray(c.objection_quality)
      ? c.objection_quality
      : [],
    notes: String(c.notes || ""),
  };
}

function asStringList(v) {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x));
}

const HANDOFF_KEY = "intelwar_adversarial_handoff";

/** @type {string | null} */
let handoffMemory = null;

function handoffStoreSet(value) {
  handoffMemory = value;
  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.setItem(HANDOFF_KEY, value);
    }
  } catch {
    /* memory remains */
  }
}

function handoffStoreGet() {
  try {
    if (typeof sessionStorage !== "undefined") {
      const raw = sessionStorage.getItem(HANDOFF_KEY);
      if (raw != null) return raw;
    }
  } catch {
    /* fall through */
  }
  return handoffMemory;
}

function handoffStoreClear() {
  handoffMemory = null;
  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem(HANDOFF_KEY);
    }
  } catch {
    /* ignore */
  }
}

/**
 * Stage a claim from .tv (or elsewhere) for the .ai workbench.
 * @param {{ claim: string, source?: string, sceneId?: string, mode?: string }} payload
 */
export function stageAdversarialHandoff(payload) {
  const claim = String(payload?.claim || "").trim();
  if (!claim) return false;
  handoffStoreSet(
    JSON.stringify({
      claim,
      source: String(payload.source || "external"),
      sceneId: payload.sceneId ? String(payload.sceneId) : "",
      mode: payload.mode || "stress",
    }),
  );
  return true;
}

/**
 * Consume staged handoff once (clears storage).
 * @returns {{ claim: string, source: string, sceneId: string, mode: string } | null}
 */
export function consumeAdversarialHandoff() {
  const raw = handoffStoreGet();
  handoffStoreClear();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    const claim = String(parsed?.claim || "").trim();
    if (!claim) return null;
    return {
      claim,
      source: String(parsed.source || "external"),
      sceneId: String(parsed.sceneId || ""),
      mode: String(parsed.mode || "stress"),
    };
  } catch {
    return null;
  }
}
