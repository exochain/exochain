/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LynkConfigurationError,
  ReceiptEmissionError,
  buildLlmUsageReceiptIntent,
  hashProviderPayload,
  resolveReceiptPending,
  type FetchLike,
  type LlmProxyConfig,
  type UsageContext,
} from "../src/index.js";
import { releaseWithReceipt } from "../src/delivery.js";
import { emitUsageReceipt, resolveFetch } from "../src/receipt.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };

function config(fetchImpl: FetchLike, mode: LlmProxyConfig["mode"] = "production"): LlmProxyConfig {
  return {
    mode,
    allowUnreceiptedOutputForDevelopment: mode === "development",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    custodyPolicyHash: hashProviderPayload("policy"),
    storageMode: "receipt_minimized",
    validation: { credential: "fixture" },
    subjectSignature: "subject-signature",
    adapterSignature: "adapter-signature",
    fetch: fetchImpl,
  };
}

function usageContext(): UsageContext {
  return {
    provider: "openai",
    providerEndpoint: "responses",
    modelId: "gpt-4.1-mini",
    requestPayload: { model: "gpt-4.1-mini" },
    responsePayload: { id: "resp_1" },
    idempotencyKey: "idem-delivery",
    usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, usage_complete: true },
    createdAt: stamp,
    issuedAt: stamp,
  };
}

test("development mode can explicitly bypass receipt release", async () => {
  const fetchImpl: FetchLike = async () => new Response("unavailable", { status: 503 });
  const cfg = config(fetchImpl, "development");
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  const result = await releaseWithReceipt(cfg, intent, { text: "development output" });

  assert.equal(result.status, "development_unreceipted");
  assert.deepEqual(result.output, { text: "development output" });
  assert.equal(result.receiptPending.status, "receipt_pending");
});

test("resolveReceiptPending replays the original receipt intent", async () => {
  let calls = 0;
  const fetchImpl: FetchLike = async () => {
    calls += 1;
    return new Response(JSON.stringify({ receipt_hash: "receipt-replayed" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const cfg = config(fetchImpl);
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
  const receipt = await resolveReceiptPending(cfg, {
    status: "receipt_pending",
    idempotencyKeyHash: intent.llm_usage_evidence.evidence.idempotency_key_hash,
    receiptIntent: intent,
  });

  assert.equal(calls, 1);
  assert.equal(receipt.receipt_hash, "receipt-replayed");
});

test("emitUsageReceipt uses global fetch fallback and trims gateway URL", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  try {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async (input: RequestInfo | URL) => {
        requestedUrl = String(input);
        return new Response(JSON.stringify({ receipt_hash: "receipt-global" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const cfg = config(undefined as unknown as FetchLike);
    delete (cfg as { fetch?: FetchLike }).fetch;
    cfg.gatewayUrl = "https://exochain.test/";
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    const receipt = await emitUsageReceipt(cfg, intent);

    assert.equal(
      requestedUrl,
      "https://exochain.test/api/v1/avc/llm-usage/receipts/emit",
    );
    assert.equal(receipt.receipt_hash, "receipt-global");
  } finally {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: originalFetch,
    });
  }
});

test("resolveFetch fails closed when no fetch implementation exists", () => {
  const originalFetch = globalThis.fetch;
  try {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: undefined,
    });
    assert.throws(() => resolveFetch(), LynkConfigurationError);
  } finally {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: originalFetch,
    });
  }
});

test("emitUsageReceipt exposes status code without leaking response body", async () => {
  const cfg = config(async () => new Response("secret receipt body", { status: 503 }));
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  await assert.rejects(
    async () => emitUsageReceipt(cfg, intent),
    (error: unknown) => {
      assert.ok(error instanceof ReceiptEmissionError);
      assert.equal(error.statusCode, 503);
      assert.equal(error.message.includes("secret receipt body"), false);
      return true;
    },
  );
});

test("non receipt emission errors are rethrown", async () => {
  const fetchImpl: FetchLike = async () => {
    throw new Error("network died before response");
  };
  const cfg = config(fetchImpl);
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  await assert.rejects(
    () => releaseWithReceipt(cfg, intent, { text: "withheld" }),
    /network died before response/,
  );
});
