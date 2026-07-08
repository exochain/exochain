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
  LynkValidationError,
  createReceiptedMcpProxy,
  hashProviderPayload,
  stableStringify,
  type FetchLike,
  type KmsLike,
  type LlmProxyConfig,
  type ObjectStoreLike,
  type ReceiptIntent,
} from "../src/index.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };

function baseConfig(fetchImpl: FetchLike): LlmProxyConfig {
  return {
    mode: "production",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    custodyPolicyHash: hashProviderPayload("policy"),
    storageMode: "receipt_minimized",
    validation: { credential: "fixture", action: "llm.usage.receipt.emit" },
    subjectSignature: "subject-signature",
    adapterSignature: "adapter-signature",
    fetch: fetchImpl,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function fakeFetch(
  receiptBodies: ReceiptIntent[],
  mcp: (url: string, body: unknown) => Response,
  receiptStatus = 200,
): FetchLike {
  return async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
      receiptBodies.push(body as ReceiptIntent);
      return jsonResponse({ receipt_hash: "receipt-mcp" }, receiptStatus);
    }
    return mcp(url, body);
  };
}

test("tools call success emits receipt and hashes arguments plus result", async () => {
  const receipts: ReceiptIntent[] = [];
  const proxy = createReceiptedMcpProxy(
    baseConfig(
      fakeFetch(receipts, (url) => {
        assert.equal(url, "https://mcp.test");
        return jsonResponse({
          jsonrpc: "2.0",
          id: "idem-mcp-1",
          result: { content: [{ type: "text", text: "secret-tool-result" }] },
        });
      }),
    ),
    { serverUrl: "https://mcp.test" },
  );

  const result = await proxy.callTool(
    { name: "search", arguments: { query: "secret-tool-argument" } },
    { idempotencyKey: "idem-mcp-1", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.provider, "mcp");
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.tool_call_hash?.length, 64);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.tool_result_hash?.length, 64);
  const serialized = stableStringify(receipts[0]);
  assert.equal(serialized.includes("secret-tool-argument"), false);
  assert.equal(serialized.includes("secret-tool-result"), false);
});

test("tools call failure emits failure receipt without raw server error", async () => {
  const receipts: ReceiptIntent[] = [];
  const proxy = createReceiptedMcpProxy(
    baseConfig(
      fakeFetch(receipts, () =>
        jsonResponse({ jsonrpc: "2.0", id: "idem-mcp-2", error: { message: "secret-error" } }, 500),
      ),
    ),
    { serverUrl: "https://mcp.test" },
  );

  const result = await proxy.callTool(
    { name: "search", arguments: { query: "secret-tool-argument" } },
    { idempotencyKey: "idem-mcp-2", createdAt: stamp },
  );

  assert.equal(result.status, "provider_error");
  assert.equal(stableStringify(result.receiptIntent).includes("secret-error"), false);
  assert.equal(receipts.length, 1);
});

test("malformed MCP response is rejected as untrusted", async () => {
  const proxy = createReceiptedMcpProxy(
    baseConfig(fakeFetch([], () => jsonResponse({ jsonrpc: "2.0", id: "bad", result: "raw" }))),
    { serverUrl: "https://mcp.test" },
  );

  await assert.rejects(
    () =>
      proxy.callTool(
        { name: "search", arguments: { query: "x" } },
        { idempotencyKey: "idem-mcp-3", createdAt: stamp },
      ),
    LynkValidationError,
  );
});

test("MCP rejects non-object and invalid jsonrpc tool results", async () => {
  for (const [payload, idempotencyKey] of [
    [["array-result"], "idem-mcp-non-object"],
    [{ jsonrpc: "1.0", id: "bad", result: { content: [] } }, "idem-mcp-bad-jsonrpc"],
  ] as const) {
    const proxy = createReceiptedMcpProxy(
      baseConfig(fakeFetch([], () => jsonResponse(payload))),
      { serverUrl: "https://mcp.test" },
    );

    await assert.rejects(
      () =>
        proxy.callTool(
          { name: "search", arguments: { query: "placeholder" } },
          { idempotencyKey, createdAt: stamp },
        ),
      LynkValidationError,
    );
  }
});

test("missing MCP server config fails before provider call", async () => {
  let calls = 0;
  const config = baseConfig(async () => {
    calls += 1;
    return jsonResponse({});
  });

  assert.throws(() => createReceiptedMcpProxy(config, {}), LynkConfigurationError);
  assert.equal(calls, 0);
});

test("empty MCP tool name fails before provider call", async () => {
  let calls = 0;
  const proxy = createReceiptedMcpProxy(
    baseConfig(
      fakeFetch([], () => {
        calls += 1;
        return jsonResponse({});
      }),
    ),
    { serverUrl: "https://mcp.test" },
  );

  await assert.rejects(
    () =>
      proxy.callTool(
        { name: " ", arguments: { topic: "placeholder" } },
        { idempotencyKey: "idem-mcp-4", createdAt: stamp },
      ),
    LynkValidationError,
  );
  assert.equal(calls, 0);
});

test("MCP provider success plus receipt failure withholds tool result", async () => {
  const receipts: ReceiptIntent[] = [];
  const proxy = createReceiptedMcpProxy(
    baseConfig(
      fakeFetch(
        receipts,
        () =>
          jsonResponse({
            jsonrpc: "2.0",
            id: "idem-mcp-5",
            result: { content: [{ type: "text", text: "secret-tool-result" }] },
          }),
        503,
      ),
    ),
    { serverUrl: "https://mcp.test" },
  );

  const result = await proxy.callTool(
    { name: "search", arguments: { topic: "placeholder" } },
    { idempotencyKey: "idem-mcp-5", createdAt: stamp },
  );

  assert.equal(result.status, "receipt_pending");
  assert.equal("output" in result, false);
  assert.equal(receipts.length, 1);
});

test("MCP external payload refs store hashed tool call and result refs", async () => {
  const receipts: ReceiptIntent[] = [];
  const writes: string[] = [];
  const kms: KmsLike = {
    encrypt: async ({ payloadKind }) => ({
      ciphertext: `ciphertext-for-${payloadKind}`,
      keyPolicyId: "customer-key-policy",
    }),
  };
  const objectStore: ObjectStoreLike = {
    put: async ({ payloadKind }) => {
      writes.push(payloadKind);
      return { refId: `opaque-ref-${payloadKind}`, storagePolicyId: "customer-store-policy" };
    },
  };
  const config = baseConfig(
    fakeFetch(receipts, () =>
      jsonResponse({
        jsonrpc: "2.0",
        id: "idem-mcp-6",
        result: { structuredContent: { count: 1 } },
      }),
    ),
  );
  config.storageMode = "external_payload_ref";
  config.kms = kms;
  config.objectStore = objectStore;
  const proxy = createReceiptedMcpProxy(config, { serverUrl: "https://mcp.test" });

  const result = await proxy.callTool(
    { name: "search", arguments: { topic: "placeholder" } },
    { idempotencyKey: "idem-mcp-6", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.deepEqual(writes, ["mcp_tool_call", "mcp_tool_result"]);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.encrypted_payload_refs.length, 2);
  assert.equal(stableStringify(receipts[0]).includes("opaque-ref-"), false);
  assert.equal(stableStringify(receipts[0]).includes("customer-key-policy"), false);
});
