// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLlmUsageReceiptIntent, hashProviderPayload, type LlmProxyConfig } from "../src/index.js";

test("each model/tool receipt gets host-signed authority for its actual evidence", async () => {
  const actions: string[] = [];
  const config: LlmProxyConfig = {
    mode: "development", gatewayUrl: "https://core.test", tenantId: "tenant",
    namespace: "default", actorDid: "did:exo:actor", adapterDid: "did:exo:adapter",
    custodyPolicyHash: hashProviderPayload("policy"), storageMode: "receipt_minimized",
    adapterSignature: "b".repeat(128),
    prepareReceipt: async evidence => {
      actions.push(evidence.action_id);
      return { validation: { action: evidence.action_id }, subjectSignature: "a".repeat(128) };
    },
  };
  for (const id of ["a".repeat(64), "b".repeat(64)]) {
    const result = await buildLlmUsageReceiptIntent(config, {
      provider: "openai", providerEndpoint: "responses", modelId: "test-model",
      requestPayload: { input: "private" }, responsePayload: { output: "private" },
      idempotencyKey: id, actionId: id,
      usage: { input_tokens: 2, output_tokens: 3, total_tokens: 5, usage_complete: true },
      createdAt: { physical_ms: 100, logical: 0 }, issuedAt: { physical_ms: 100, logical: 0 },
    });
    assert.deepEqual(result.validation, { action: id });
    assert.equal(result.subject_signature, "a".repeat(128));
  }
  assert.deepEqual(actions, ["a".repeat(64), "b".repeat(64)]);
});
