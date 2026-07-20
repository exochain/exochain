import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CEILINGS_MICRO_USD,
  DEFAULT_MODELS,
  ceilingDecision,
  estimateCostMicroUsd,
  loadModelCatalog,
  openRouterConfigured,
} from "./adversarial.js";
import {
  campaignZeroStatus,
  foundingEntries,
  foundingEntryPayload,
  isCampaignZeroEntry,
} from "./campaign-zero.js";

describe("adversarial catalog", () => {
  it("defaults are multi-model not single-locked", () => {
    const ids = Object.values(DEFAULT_MODELS);
    assert.ok(new Set(ids).size >= 5);
    assert.ok(ids.every((m) => m.includes("/")));
    assert.equal(DEFAULT_MODELS.primary, "anthropic/claude-fable-5");
    assert.equal(DEFAULT_MODELS.alternate, "openai/gpt-5.6-sol-pro");
    assert.equal(DEFAULT_MODELS.auditor, "google/gemini-3.1-pro-preview");
    assert.equal(DEFAULT_MODELS.synthesizer, "x-ai/grok-latest");
    assert.equal(DEFAULT_MODELS.maverick, "meta-llama/llama-4-maverick");
  });

  it("loadModelCatalog merges overrides", () => {
    const prev = process.env.INTELWAR_ADVERSARIAL_MODELS;
    process.env.INTELWAR_ADVERSARIAL_MODELS = JSON.stringify({
      primary: "test/provider-model",
    });
    const cat = loadModelCatalog();
    assert.equal(cat.primary, "test/provider-model");
    assert.equal(cat.alternate, DEFAULT_MODELS.alternate);
    if (prev === undefined) delete process.env.INTELWAR_ADVERSARIAL_MODELS;
    else process.env.INTELWAR_ADVERSARIAL_MODELS = prev;
  });

  it("openRouterConfigured reflects env", () => {
    const prev = process.env.OPENROUTER_API_KEY;
    delete process.env.OPENROUTER_API_KEY;
    assert.equal(openRouterConfigured(), false);
    process.env.OPENROUTER_API_KEY = "sk-test";
    assert.equal(openRouterConfigured(), true);
    if (prev === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = prev;
  });
});

describe("cost ceilings (COST_MODEL v1.2)", () => {
  it("binding ceilings match the cost model", () => {
    assert.equal(CEILINGS_MICRO_USD.stress_test, 150_000);
    assert.equal(CEILINGS_MICRO_USD.cross_check, 350_000);
    assert.equal(CEILINGS_MICRO_USD.red_team, 1_000_000);
  });

  it("estimateCostMicroUsd prefers provider cost, integer micro-USD", () => {
    const fromProvider = estimateCostMicroUsd("anthropic/claude-fable-5", {
      cost: 0.032,
    });
    assert.equal(fromProvider.cost_micro_usd, 32_000);
    assert.equal(fromProvider.cost_source, "openrouter");

    const estimated = estimateCostMicroUsd("anthropic/claude-fable-5", {
      prompt_tokens: 1_400,
      completion_tokens: 900,
    });
    // 1400 * $5/M + 900 * $25/M = 7000 + 22500 micro-USD
    assert.equal(estimated.cost_micro_usd, 29_500);
    assert.equal(estimated.cost_source, "estimated");
    assert.ok(Number.isInteger(estimated.cost_micro_usd));
  });

  it("unknown model falls back to conservative frontier pricing", () => {
    const est = estimateCostMicroUsd("unknown/model", {
      prompt_tokens: 1_000_000,
      completion_tokens: 0,
    });
    assert.equal(est.cost_micro_usd, 5_000_000);
  });

  it("ceilingDecision proceeds, downgrades at 80%, stops at 100%", () => {
    const base = {
      mode: "stress_test",
      requestedModel: "anthropic/claude-fable-5",
      budgetModel: "meta-llama/llama-4-maverick",
    };
    assert.equal(
      ceilingDecision({ ...base, spentMicroUsd: 0 }).action,
      "proceed",
    );
    const down = ceilingDecision({ ...base, spentMicroUsd: 120_000 });
    assert.equal(down.action, "downgrade");
    assert.equal(down.model, "meta-llama/llama-4-maverick");
    const stop = ceilingDecision({ ...base, spentMicroUsd: 150_000 });
    assert.equal(stop.action, "stop");
    assert.equal(stop.spent_bps, 10_000);
  });

  it("budget model at 80%+ proceeds without further downgrade", () => {
    const d = ceilingDecision({
      mode: "cross_check",
      spentMicroUsd: 300_000,
      requestedModel: "meta-llama/llama-4-maverick",
      budgetModel: "meta-llama/llama-4-maverick",
    });
    assert.equal(d.action, "proceed");
  });
});

describe("campaign zero", () => {
  it("founding entries are flagged, attested, deterministic", () => {
    const a = foundingEntries();
    const b = foundingEntries();
    assert.deepEqual(a, b);
    assert.ok(a.length >= 9);
    for (const e of a) {
      assert.match(e.summary, /^CZ-\d\d /);
      const payload = JSON.parse(foundingEntryPayload(e));
      assert.equal(payload.campaign, "campaign-zero");
      assert.equal(payload.founding, true);
      assert.equal(payload.seed, true);
      assert.equal(payload.merit_scope, "sandboxed");
      assert.ok(payload.attestation.length > 0);
      if (e.voice_kind === "synthetic") {
        assert.match(payload.attestation, /identity unrecorded/);
      }
    }
  });

  it("status detects missing vs seeded via mirror summaries", () => {
    const none = campaignZeroStatus([]);
    assert.equal(none.seeded, 0);
    assert.equal(none.complete, false);

    const mirror = foundingEntries().map((e) => ({ summary: e.summary }));
    const full = campaignZeroStatus(mirror);
    assert.equal(full.complete, true);
    assert.deepEqual(full.missing_codes, []);
    assert.ok(isCampaignZeroEntry(mirror[0]));
    assert.equal(isCampaignZeroEntry({ summary: "regular entry" }), false);
  });
});
