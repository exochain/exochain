/**
 * OpenRouter adversarial engine for intelwar.ai
 * Multi-Intelligence Transparency: every run carries model identity.
 * AI outputs are never final authority.
 */

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

/**
 * Default frontier catalog (OpenRouter slugs).
 * Not hard-coupled — override via INTELWAR_ADVERSARIAL_MODELS JSON.
 */
export const DEFAULT_MODELS = {
  primary: "anthropic/claude-fable-5",
  alternate: "openai/gpt-5.6-sol-pro",
  auditor: "google/gemini-3.1-pro-preview",
  synthesizer: "x-ai/grok-latest",
  maverick: "meta-llama/llama-4-maverick",
};

/** Ordered roster for multi-model comparison views */
export const FRONTIER_ROSTER = [
  DEFAULT_MODELS.primary,
  DEFAULT_MODELS.alternate,
  DEFAULT_MODELS.auditor,
  DEFAULT_MODELS.synthesizer,
  DEFAULT_MODELS.maverick,
];

/**
 * Binding session cost ceilings (COST_MODEL.md v1.2), integer micro-USD.
 * $0.15 Stress Test / $0.35 Cross-Check / $1.00 Red Team.
 */
export const CEILINGS_MICRO_USD = {
  stress_test: 150_000,
  cross_check: 350_000,
  red_team: 1_000_000,
};

/** Auto-downgrade to budget tier at 80% of ceiling (8000 bps). */
export const DOWNGRADE_AT_BPS = 8_000;

/**
 * Reference OpenRouter list pricing, integer micro-USD per 1M tokens.
 * Unknown models fall back to conservative frontier pricing.
 */
const MODEL_PRICES_MICRO_PER_MTOK = {
  "anthropic/claude-fable-5": { input: 5_000_000, output: 25_000_000 },
  "openai/gpt-5.6-sol-pro": { input: 5_000_000, output: 30_000_000 },
  "google/gemini-3.1-pro-preview": { input: 2_500_000, output: 15_000_000 },
  "x-ai/grok-latest": { input: 3_000_000, output: 15_000_000 },
  "meta-llama/llama-4-maverick": { input: 300_000, output: 1_200_000 },
};

const FALLBACK_PRICE = { input: 5_000_000, output: 30_000_000 };

export const DISCLOSURE =
  "Generated adversarial analysis — NOT certification of truth, accuracy, fair use, non-infringement, or non-defamation.";

/**
 * Estimate call cost in integer micro-USD.
 * Prefers provider-reported cost (converted at the boundary), else token table.
 * @param {string} model
 * @param {{ prompt_tokens?: number, completion_tokens?: number, cost?: number } | null} usage
 * @returns {{ cost_micro_usd: number, cost_source: 'openrouter'|'estimated' }}
 */
export function estimateCostMicroUsd(model, usage) {
  const u = usage && typeof usage === "object" ? usage : {};
  if (typeof u.cost === "number" && Number.isFinite(u.cost) && u.cost >= 0) {
    return {
      cost_micro_usd: Math.ceil(u.cost * 1_000_000),
      cost_source: "openrouter",
    };
  }
  const price = MODEL_PRICES_MICRO_PER_MTOK[model] || FALLBACK_PRICE;
  const tin = Number.isInteger(u.prompt_tokens) ? u.prompt_tokens : 1_400;
  const tout = Number.isInteger(u.completion_tokens) ? u.completion_tokens : 900;
  const cost =
    Math.ceil((tin * price.input) / 1_000_000) +
    Math.ceil((tout * price.output) / 1_000_000);
  return { cost_micro_usd: cost, cost_source: "estimated" };
}

/** In-memory per-session spend meter (single-replica v1). */
const sessionSpend = new Map();
const SESSION_CAP = 1_000;

/**
 * @param {string} sessionId
 * @returns {number} spent micro-USD
 */
export function sessionSpentMicroUsd(sessionId) {
  return sessionSpend.get(sessionId) || 0;
}

function addSessionSpend(sessionId, microUsd) {
  if (sessionSpend.size >= SESSION_CAP && !sessionSpend.has(sessionId)) {
    const oldest = sessionSpend.keys().next().value;
    sessionSpend.delete(oldest);
  }
  sessionSpend.set(sessionId, (sessionSpend.get(sessionId) || 0) + microUsd);
}

/** Test-only reset for the session meter. */
export function resetSessionSpendForTest() {
  sessionSpend.clear();
}

/**
 * Ceiling decision for the next model call in a session.
 * @param {{ mode: keyof typeof CEILINGS_MICRO_USD, spentMicroUsd: number, requestedModel: string, budgetModel: string }} p
 * @returns {{ action: 'proceed'|'downgrade'|'stop', model: string, spent_bps: number, ceiling_micro_usd: number }}
 */
export function ceilingDecision({ mode, spentMicroUsd, requestedModel, budgetModel }) {
  const ceiling = CEILINGS_MICRO_USD[mode] || CEILINGS_MICRO_USD.stress_test;
  const spentBps = Math.min(
    10_000,
    Math.floor((spentMicroUsd * 10_000) / ceiling),
  );
  if (spentMicroUsd >= ceiling) {
    return {
      action: "stop",
      model: requestedModel,
      spent_bps: spentBps,
      ceiling_micro_usd: ceiling,
    };
  }
  if (spentBps >= DOWNGRADE_AT_BPS && requestedModel !== budgetModel) {
    return {
      action: "downgrade",
      model: budgetModel,
      spent_bps: spentBps,
      ceiling_micro_usd: ceiling,
    };
  }
  return {
    action: "proceed",
    model: requestedModel,
    spent_bps: spentBps,
    ceiling_micro_usd: ceiling,
  };
}

/**
 * @returns {typeof DEFAULT_MODELS}
 */
export function loadModelCatalog() {
  const raw = String(process.env.INTELWAR_ADVERSARIAL_MODELS || "").trim();
  if (!raw) return { ...DEFAULT_MODELS };
  try {
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_MODELS, ...parsed };
  } catch {
    return { ...DEFAULT_MODELS };
  }
}

export function openRouterConfigured() {
  return Boolean(String(process.env.OPENROUTER_API_KEY || "").trim());
}

/**
 * @param {object} opts
 * @param {string} opts.model
 * @param {string} opts.system
 * @param {string} opts.user
 * @param {number} [opts.maxTokens]
 */
export async function callOpenRouter({ model, system, user, maxTokens = 4096 }) {
  const key = String(process.env.OPENROUTER_API_KEY || "").trim();
  if (!key) {
    const err = new Error("OPENROUTER_API_KEY required");
    err.code = "openrouter_unconfigured";
    throw err;
  }

  const res = await fetch(OPENROUTER_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://intelwar.ai",
      "X-Title": "IntelWar Adversarial Layer",
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      max_tokens: maxTokens,
      response_format: { type: "json_object" },
      usage: { include: true },
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    }),
  });

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(
      body?.error?.message || `OpenRouter HTTP ${res.status}`,
    );
    err.code = "openrouter_http_error";
    err.status = res.status;
    err.detail = body;
    throw err;
  }

  const content = body?.choices?.[0]?.message?.content || "";
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    parsed = { raw_text: content, parse_error: true };
  }

  return {
    model: body.model || model,
    model_requested: model,
    provider: "openrouter",
    voice_kind: "synthetic",
    usage: body.usage || null,
    id: body.id || null,
    content: parsed,
    raw_content: content,
  };
}

const STRESS_SYSTEM = `You are an adversarial analytical instrument in the IntelWar theatre.
You are NOT a helpful general assistant and NOT a final authority on truth.
Posture: adversarial but fair. Steelmanning before attacking when asked.
Return ONLY valid JSON with this exact schema:
{
  "strongest_interpretation": "string",
  "key_vulnerabilities": ["string"],
  "strongest_counters": ["string"],
  "evidence_gaps": ["string"],
  "fortifications": ["string"],
  "objection_quality": [{"objection":"string","strength":"strong|moderate|weak"}],
  "notes": "string"
}
Be precise, severe, and scannable. Distinguish strong vs weak objections.`;

const CROSSCHECK_SYSTEM = `You are a multi-intelligence cross-check auditor for IntelWar.
Never declare final truth. Assess consistency, evidence, contradictions, assumptions.
Return ONLY valid JSON:
{
  "consistency": {"rating":"high|medium|low|unknown","notes":"string"},
  "evidence_strength": {"rating":"strong|moderate|weak|unknown","notes":"string"},
  "contradictions": ["string"],
  "unstated_assumptions": ["string"],
  "verdict_hint": "support|challenge|abstain",
  "summary": "string"
}`;

const ROLE_SYSTEM = {
  advocate: `You are the Advocate. Argue the strongest charitable case. JSON: {"role":"advocate","case":"string","key_points":["string"]}`,
  attacker: `You are the Attacker. Find the strongest defeaters. JSON: {"role":"attacker","attacks":["string"],"fatal_flaws":["string"]}`,
  evidence_auditor: `You are the Evidence Auditor. Scrutinize evidence claims only. JSON: {"role":"evidence_auditor","supported":["string"],"unsupported":["string"],"missing":["string"]}`,
  synthesizer: `You are the Synthesizer. Integrate without declaring absolute truth. JSON: {"role":"synthesizer","map":"string","remaining_disagreements":["string"],"next_tests":["string"]}`,
};

/**
 * @param {object} input
 * @param {'stress_test'|'cross_check'|'red_team'} input.mode
 * @param {string} input.claim
 * @param {string[]} [input.focus]
 * @param {boolean} [input.steelman_first]
 * @param {string[]} [input.models]
 * @param {string[]} [input.roles]
 * @param {string} [input.session_id]
 */
export async function runAdversarial(input) {
  const catalog = loadModelCatalog();
  const mode = input.mode || "stress_test";
  const claim = String(input.claim || "").trim();
  if (!claim || claim.length < 8) {
    const err = new Error("claim required (min 8 chars)");
    err.code = "claim_required";
    throw err;
  }
  if (claim.length > 12000) {
    const err = new Error("claim too long (max 12000)");
    err.code = "claim_too_long";
    throw err;
  }

  const sessionId =
    typeof input.session_id === "string" && input.session_id.trim()
      ? input.session_id.trim().slice(0, 80)
      : `anon-${Date.now()}`;
  const budgetModel = catalog.maverick;
  const ceiling =
    CEILINGS_MICRO_USD[mode] || CEILINGS_MICRO_USD.stress_test;

  const started = Date.now();
  /** @type {Array<Record<string, unknown>>} */
  const runs = [];
  /** @type {Array<Record<string, unknown>>} */
  const skipped = [];
  let downgraded = false;
  let hardStopped = false;

  /**
   * Ceiling-metered OpenRouter call. Returns null when hard-stopped.
   * @param {{ model: string, system: string, user: string, maxTokens?: number, role?: string }} p
   */
  async function meteredCall({ model, system, user, maxTokens, role }) {
    const decision = ceilingDecision({
      mode,
      spentMicroUsd: sessionSpentMicroUsd(sessionId),
      requestedModel: model,
      budgetModel,
    });
    if (decision.action === "stop") {
      hardStopped = true;
      skipped.push({
        model_requested: model,
        role: role || null,
        reason: "cost_ceiling_reached",
      });
      return null;
    }
    if (decision.action === "downgrade") downgraded = true;
    const result = await callOpenRouter({
      model: decision.model,
      system,
      user,
      maxTokens,
    });
    const { cost_micro_usd, cost_source } = estimateCostMicroUsd(
      result.model,
      result.usage,
    );
    addSessionSpend(sessionId, cost_micro_usd);
    return {
      ...result,
      role: role || undefined,
      cost_micro_usd,
      cost_source,
      downgraded_from: decision.action === "downgrade" ? model : undefined,
    };
  }

  if (mode === "stress_test") {
    const model = (input.models && input.models[0]) || catalog.primary;
    const focus = Array.isArray(input.focus) ? input.focus : [];
    const steelman = input.steelman_first !== false;
    const user = [
      `CLAIM / ARGUMENT:\n${claim}`,
      `FOCUS: ${focus.length ? focus.join(", ") : "logical structure, evidence, assumptions, counters"}`,
      `STEELMAN_FIRST: ${steelman}`,
      "Produce the JSON schema now.",
    ].join("\n\n");
    const result = await meteredCall({ model, system: STRESS_SYSTEM, user });
    if (result) runs.push(result);
  } else if (mode === "cross_check") {
    const models = uniqueModels(
      input.models?.length
        ? input.models
        : [
            catalog.primary,
            catalog.alternate,
            catalog.auditor,
            catalog.synthesizer,
            catalog.maverick,
          ],
    ).slice(0, 5);
    for (const model of models) {
      const user = `SUBJECT CLAIM:\n${claim}\n\nCross-check under IntelWar rules. JSON only.`;
      // sequential to respect rate limits and the session cost meter
      // eslint-disable-next-line no-await-in-loop
      const result = await meteredCall({
        model,
        system: CROSSCHECK_SYSTEM,
        user,
        maxTokens: 2500,
      });
      if (result) runs.push(result);
    }
  } else if (mode === "red_team") {
    const roles = input.roles?.length
      ? input.roles
      : ["advocate", "attacker", "evidence_auditor", "synthesizer"];
    const roleModels = {
      advocate: catalog.alternate,
      attacker: catalog.primary,
      evidence_auditor: catalog.auditor,
      synthesizer: catalog.synthesizer,
      maverick: catalog.maverick,
    };
    for (const role of roles) {
      const system = ROLE_SYSTEM[role] || ROLE_SYSTEM.attacker;
      const model = roleModels[role] || catalog.primary;
      const user = `SUBJECT:\n${claim}\n\nExecute your role. JSON only.`;
      // eslint-disable-next-line no-await-in-loop
      const result = await meteredCall({
        model,
        system,
        user,
        maxTokens: 2000,
        role,
      });
      if (result) runs.push(result);
    }
  } else {
    const err = new Error(`unknown mode: ${mode}`);
    err.code = "unknown_mode";
    throw err;
  }

  const spent = sessionSpentMicroUsd(sessionId);
  const cost = {
    session_id: sessionId,
    mode,
    spent_micro_usd: spent,
    ceiling_micro_usd: ceiling,
    spent_bps: Math.min(10_000, Math.floor((spent * 10_000) / ceiling)),
    downgraded,
    hard_stopped: hardStopped,
    state: hardStopped ? "command_review" : "within_ceiling",
    enforcement: "meter + auto-downgrade at 80% + graceful stop at 100%",
  };

  if (hardStopped && runs.length === 0) {
    // Command Review: no new model calls, but the session transcript is
    // retained client-side — never a raw 429.
    return {
      ok: true,
      mode,
      claim,
      provider: "openrouter",
      voice_kind: "synthetic",
      final_authority: false,
      multi_intelligence_transparency: true,
      disclosure: DISCLOSURE,
      elapsed_ms: Date.now() - started,
      models_used: [],
      runs: [],
      skipped,
      cost,
      command_review: true,
      note: "Session cost ceiling reached. Annotate, synthesize, and commit existing transcript — no further model calls this session.",
    };
  }

  return {
    ok: true,
    mode,
    claim,
    provider: "openrouter",
    voice_kind: "synthetic",
    final_authority: false,
    multi_intelligence_transparency: true,
    disclosure: DISCLOSURE,
    elapsed_ms: Date.now() - started,
    models_used: runs.map((r) => r.model),
    runs,
    skipped: skipped.length ? skipped : undefined,
    cost,
    command_review: hardStopped,
    artifact_draft: buildArtifactDraft(mode, claim, runs, cost),
    note: "AI analysis is not final authority. Promote to Living Log only with consent + Kernel path.",
  };
}

function uniqueModels(list) {
  return [...new Set(list.filter(Boolean))];
}

function buildArtifactDraft(mode, claim, runs, cost) {
  return {
    entry_kind: "AdversarialAnalysis",
    event_type: `analysis.${mode}`,
    summary: `${mode}: ${claim.slice(0, 120)}`,
    voice_kind: "synthetic",
    model_ids: runs.map((r) => r.model),
    provider: "openrouter",
    disclosure: DISCLOSURE,
    cost_micro_usd: cost ? cost.spent_micro_usd : 0,
    sections: runs.map((r) => ({
      model: r.model,
      role: r.role || null,
      cost_micro_usd: r.cost_micro_usd || 0,
      content: r.content,
    })),
    provenance: {
      multi_intelligence: true,
      final_authority: false,
      eligible_for_log: true,
      requires_consent: true,
      merit_scope: "provisional",
      attestation_note:
        "Attestation is audit metadata, not proof of accuracy.",
    },
  };
}
