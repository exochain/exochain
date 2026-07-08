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
  createReceiptedOpenAIClient,
  hashProviderPayload,
  stableStringify,
  type FetchLike,
  type KmsLike,
  type LlmProxyConfig,
  type ObjectStoreLike,
  type ReceiptIntent,
} from "../src/index.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function baseConfig(
  fetchImpl: FetchLike,
  kms: KmsLike,
  objectStore: ObjectStoreLike,
): LlmProxyConfig {
  return {
    mode: "production",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    custodyPolicyHash: hashProviderPayload("policy"),
    storageMode: "external_payload_ref",
    validation: { credential: "fixture", action: "llm.usage.receipt.emit" },
    subjectSignature: "subject-signature",
    adapterSignature: "adapter-signature",
    fetch: fetchImpl,
    kms,
    objectStore,
  };
}

function fakeFetch(receipts: ReceiptIntent[], receiptStatus = 200): FetchLike {
  return async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
      receipts.push(body as ReceiptIntent);
      return jsonResponse({ receipt_hash: "receipt-object" }, receiptStatus);
    }
    return jsonResponse({
      id: "resp-object",
      output: [{ text: "secret-output" }],
      usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 },
    });
  };
}

test("external payload ref writes encrypted blobs and receipts only hashed refs", async () => {
  const receipts: ReceiptIntent[] = [];
  const writes: string[] = [];
  const kms: KmsLike = {
    encrypt: async ({ payloadKind }) => ({
      ciphertext: `ciphertext-for-${payloadKind}`,
      keyPolicyId: "kms-key-prod",
    }),
  };
  const objectStore: ObjectStoreLike = {
    put: async ({ payloadKind }) => {
      writes.push(payloadKind);
      return {
        refId: `s3://customer-bucket/raw/${payloadKind}`,
        storagePolicyId: "customer-store-policy",
      };
    },
  };
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch(receipts), kms, objectStore),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.responses.create(
    { model: "gpt-4.1-mini", input: "secret-prompt" },
    { idempotencyKey: "idem-object-1", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.deepEqual(writes, ["openai_request", "openai_response"]);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.encrypted_payload_refs.length, 2);
  const serialized = stableStringify(receipts[0]);
  assert.equal(serialized.includes("s3://customer-bucket"), false);
  assert.equal(serialized.includes("kms-key-prod"), false);
  assert.equal(serialized.includes("secret-prompt"), false);
  assert.equal(serialized.includes("secret-output"), false);
});

test("KMS failure blocks decryptable external storage", async () => {
  const kms: KmsLike = {
    encrypt: async () => {
      throw new Error("kms unavailable");
    },
  };
  const objectStore: ObjectStoreLike = {
    put: async () => ({ refId: "s3://unused", storagePolicyId: "unused" }),
  };
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch([]), kms, objectStore),
    { openAIBaseUrl: "https://openai.test" },
  );

  await assert.rejects(
    () =>
      client.responses.create(
        { model: "gpt-4.1-mini", input: "secret-prompt" },
        { idempotencyKey: "idem-object-2", createdAt: stamp },
      ),
    /kms unavailable/,
  );
});

test("object store success plus receipt failure returns receipt pending", async () => {
  const receipts: ReceiptIntent[] = [];
  const kms: KmsLike = {
    encrypt: async ({ payloadKind }) => ({
      ciphertext: `ciphertext-for-${payloadKind}`,
      keyPolicyId: "kms-key-prod",
    }),
  };
  const objectStore: ObjectStoreLike = {
    put: async ({ payloadKind }) => ({
      refId: `s3://customer-bucket/raw/${payloadKind}`,
      storagePolicyId: "customer-store-policy",
    }),
  };
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch(receipts, 503), kms, objectStore),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.responses.create(
    { model: "gpt-4.1-mini", input: "secret-prompt" },
    { idempotencyKey: "idem-object-3", createdAt: stamp },
  );

  assert.equal(result.status, "receipt_pending");
  assert.equal("output" in result, false);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.encrypted_payload_refs.length, 2);
});
