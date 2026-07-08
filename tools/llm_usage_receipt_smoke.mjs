#!/usr/bin/env node
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

import { readdir, stat } from "node:fs/promises";

const packageRoot = new URL("../packages/exochain-llm-proxy/", import.meta.url);
await assertDistFresh(packageRoot);
const {
  createReceiptedMcpProxy,
  createReceiptedOpenAIClient,
  hashProviderPayload,
  stableStringify,
} = await import("../packages/exochain-llm-proxy/dist/index.js");

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1]);
}

const fixture = args.get("--fixture") ?? "fake-openai";
const storageMode = args.get("--storage-mode") ?? "receipt_minimized";
const expectedFailure = args.get("--expect-failure");
if (!["fake-openai", "fake-mcp"].includes(fixture)) {
  throw new Error("--fixture must be fake-openai or fake-mcp");
}
if (!["receipt_minimized", "external_payload_ref", "dagdb_custody"].includes(storageMode)) {
  throw new Error("--storage-mode must be receipt_minimized, external_payload_ref, or dagdb_custody");
}
if (
  expectedFailure &&
  ![
    "receipt_unavailable",
    "idempotency_conflict",
    "missing_custody",
    "dagdb_custody_unavailable",
    "tenant_mismatch",
    "incomplete_usage_required",
  ].includes(expectedFailure)
) {
  throw new Error("--expect-failure must name a supported smoke failure case");
}

const emittedReceipts = new Map();
const objectWrites = [];
const stamp = { physical_ms: 1_700_000, logical: 0 };
let sequence = 0;
const receiptFailureStatus =
  expectedFailure === "receipt_unavailable"
    ? 503
    : expectedFailure === "idempotency_conflict"
      ? 409
      : 200;
const expectedTenant = expectedFailure === "tenant_mismatch" ? "tenant-beta" : "tenant-alpha";

const fetchImpl = async (input, init) => {
  const url = String(input);
  const body = init?.body ? JSON.parse(String(init.body)) : undefined;
  if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
    assertNoRawPayload(body, "receipt emit body");
    if (body.llm_usage_evidence.evidence.tenant_id !== expectedTenant) {
      return jsonResponse({ error: "tenant mismatch" }, 409);
    }
    if (receiptFailureStatus !== 200) {
      return jsonResponse({ error: "receipt unavailable" }, receiptFailureStatus);
    }
    sequence += 1;
    const receiptHash = `smoke-receipt-${sequence}`;
    emittedReceipts.set(receiptHash, {
      receipt_hash: receiptHash,
      receipt: {
        receipt_id: receiptHash,
        llm_usage_evidence_hash: hashProviderPayload(body.llm_usage_evidence.evidence),
      },
      validation: { decision: "Allow" },
    });
    return jsonResponse(emittedReceipts.get(receiptHash));
  }
  if (url.includes("/api/v1/avc/receipts/")) {
    const receiptHash = decodeURIComponent(url.split("/").pop() ?? "");
    const receipt = emittedReceipts.get(receiptHash);
    if (!receipt) {
      return jsonResponse({ error: "missing receipt" }, 404);
    }
    return jsonResponse(receipt.receipt);
  }
  if (url.endsWith("/v1/responses")) {
    if (expectedFailure === "incomplete_usage_required") {
      return jsonResponse({
        id: "resp_smoke_incomplete",
        output: [{ type: "message", content: [{ type: "output_text", text: "secret-output" }] }],
      });
    }
    return jsonResponse({
      id: "resp_smoke",
      output: [{ type: "message", content: [{ type: "output_text", text: "secret-output" }] }],
      usage: {
        input_tokens: 8,
        input_tokens_details: { cached_tokens: 1 },
        output_tokens: 3,
        output_tokens_details: { reasoning_tokens: 1 },
        total_tokens: 11,
      },
    });
  }
  if (url === "https://mcp-smoke.test") {
    return jsonResponse({
      jsonrpc: "2.0",
      id: "smoke-mcp",
      result: { content: [{ type: "text", text: "secret-tool-result" }] },
    });
  }
  return jsonResponse({ error: `unexpected URL ${url}` }, 500);
};

const config = {
  mode: "production",
  gatewayUrl: "https://exochain-smoke.test",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:adapter",
  custodyPolicyHash: hashProviderPayload("smoke-policy"),
  storageMode: expectedFailure === "missing_custody" ? undefined : storageMode,
  requireCompleteUsage: expectedFailure === "incomplete_usage_required",
  validation: { credential: "smoke", action: "llm.usage.receipt.emit" },
  subjectSignature: "subject-signature",
  adapterSignature: "adapter-signature",
  fetch: fetchImpl,
  kms: {
    encrypt: async ({ payloadKind }) => ({
      ciphertext: `ciphertext-${payloadKind}`,
      keyPolicyId: "customer-kms-policy",
    }),
  },
  objectStore: {
    put: async ({ payloadKind }) => {
      objectWrites.push(payloadKind);
      return {
        refId: `customer://opaque/${payloadKind}`,
        storagePolicyId: "customer-object-policy",
      };
    },
  },
};

let result;
try {
  if (storageMode === "dagdb_custody") {
    throw new Error("dagdb_custody smoke requires governed DAG DB custody proof");
  }
  if (fixture === "fake-openai") {
    const client = createReceiptedOpenAIClient(config, {
      openAIBaseUrl: "https://openai-smoke.test",
    });
    result = await client.responses.create(
      { model: "gpt-4.1-mini", input: "secret-prompt" },
      { idempotencyKey: `smoke-${fixture}-${storageMode}`, createdAt: stamp },
    );
  } else {
    const proxy = createReceiptedMcpProxy(config, { serverUrl: "https://mcp-smoke.test" });
    result = await proxy.callTool(
      { name: "search", arguments: { query: "secret-tool-argument" } },
      { idempotencyKey: `smoke-${fixture}-${storageMode}`, createdAt: stamp },
    );
  }
} catch (error) {
  if (
    expectedFailure === "missing_custody" ||
    expectedFailure === "dagdb_custody_unavailable" ||
    expectedFailure === "incomplete_usage_required"
  ) {
    console.log(
      JSON.stringify({
        fixture,
        storage_mode: storageMode,
        status: "expected_failure_ok",
        failure_case: expectedFailure,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exit(0);
  }
  throw error;
}

if (expectedFailure) {
  if (
    !["receipt_unavailable", "idempotency_conflict", "tenant_mismatch"].includes(expectedFailure)
  ) {
    throw new Error(`failure case ${expectedFailure} unexpectedly succeeded`);
  }
  if (result.status !== "receipt_pending" || "output" in result) {
    throw new Error(`failure case ${expectedFailure} did not withhold output`);
  }
  assertNoRawPayload(result.receiptIntent, "pending receipt intent");
  console.log(
    JSON.stringify({
      fixture,
      storage_mode: storageMode,
      status: "expected_failure_ok",
      failure_case: expectedFailure,
      pending_idempotency: result.idempotencyKeyHash,
    }),
  );
  process.exit(0);
}

if (result.status !== "receipted") {
  throw new Error(`expected receipted smoke result, got ${result.status}`);
}

const receiptHash = result.receipt.receipt_hash;
const lookup = await fetchImpl(`https://exochain-smoke.test/api/v1/avc/receipts/${receiptHash}`);
if (!lookup.ok) {
  throw new Error("receipt lookup failed");
}
const fetchedReceipt = await lookup.json();
if (fetchedReceipt.receipt_id !== receiptHash) {
  throw new Error("receipt lookup did not return emitted receipt");
}
assertNoRawPayload(result.receiptIntent, "receipt intent");

console.log(
  JSON.stringify({
    fixture,
    storage_mode: storageMode,
    status: "ok",
    receipt_hash: receiptHash,
    encrypted_payload_refs:
      result.receiptIntent.llm_usage_evidence.evidence.encrypted_payload_refs.length,
    object_writes: objectWrites.length,
  }),
);

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function assertNoRawPayload(value, context) {
  const serialized = stableStringify(value);
  for (const forbidden of [
    "secret-prompt",
    "secret-output",
    "secret-tool-argument",
    "secret-tool-result",
    "provider_api_key",
    "bearer_token",
    "kms_key",
    "customer://opaque",
  ]) {
    if (serialized.includes(forbidden)) {
      throw new Error(`${context} leaked forbidden payload material: ${forbidden}`);
    }
  }
}

async function assertDistFresh(rootUrl) {
  const distIndex = new URL("dist/index.js", rootUrl);
  const distStat = await stat(distIndex);
  const newestSourceMtime = await newestMtime(new URL("src/", rootUrl));
  if (newestSourceMtime > distStat.mtimeMs) {
    throw new Error("packages/exochain-llm-proxy/dist is stale; run npm run build first");
  }
}

async function newestMtime(directoryUrl) {
  let newest = 0;
  for (const entry of await readdir(directoryUrl, { withFileTypes: true })) {
    const childUrl = new URL(entry.name, directoryUrl);
    if (entry.isDirectory()) {
      newest = Math.max(newest, await newestMtime(new URL(`${entry.name}/`, directoryUrl)));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      newest = Math.max(newest, (await stat(childUrl)).mtimeMs);
    }
  }
  return newest;
}
