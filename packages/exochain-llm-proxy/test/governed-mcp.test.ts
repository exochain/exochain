// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  createReceiptedMcpProxy, hashProviderPayload,
  type LlmProxyConfig, type McpAuthorization,
} from "../src/index.js";
import { FileExecutionJournal } from "../src/execution-journal.js";
import { actionResponse, prepareAction } from "./action-fixture.js";
import { committedReceiptResponse, TEST_VALIDATOR_DID, TEST_VALIDATOR_PUBLIC_KEY } from "./receipt-fixture.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };
async function harness(modify?: (response: any, request: any) => any) {
  const directory = await mkdtemp(join(tmpdir(), "exo-governed-mcp-"));
  const events: string[] = [];
  const calls: any[] = [];
  const config: LlmProxyConfig = {
    mode: "production", gatewayUrl: "https://exochain.test", tenantId: "tenant-alpha",
    namespace: "default", actorDid: "did:exo:agent", adapterDid: "did:exo:adapter",
    trustedValidatorDid: TEST_VALIDATOR_DID, trustedValidatorPublicKey: TEST_VALIDATOR_PUBLIC_KEY,
    custodyPolicyHash: hashProviderPayload("policy"), storageMode: "receipt_minimized",
    validation: { credential: "fixture", action: "llm.usage.receipt.emit" },
    subjectSignature: "a".repeat(128), adapterSignature: "b".repeat(128),
    fetch: async (url, init) => {
      const request = JSON.parse(String(init?.body));
      if (String(url).endsWith("/api/v1/avc/receipts/emit")) {
        events.push("authorize");
        let response = actionResponse(request);
        response = modify?.(response, request) ?? response;
        return Response.json(response);
      }
      if (String(url).endsWith("/llm-usage/receipts/emit")) {
        events.push("receipt");
        return Response.json(committedReceiptResponse(request));
      }
      events.push("execute");
      assert.equal(init?.redirect, "error");
      calls.push(request);
      return Response.json({ jsonrpc: "2.0", id: request.id, result: { content: [] } });
    },
  };
  const authorization: McpAuthorization = {
    prepare: prepareAction, now: () => ({ ...stamp }),
    journal: new FileExecutionJournal(directory),
  };
  return {
    config, authorization, events, calls,
    proxy: () => createReceiptedMcpProxy(config, { serverUrl: "https://mcp.test", authorization }),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

test("MCP authorizes the exact request before dispatch and receipts before release", async () => {
  const h = await harness();
  try {
    const result = await h.proxy().callTool({ name: "write", arguments: { value: "private" } },
      { idempotencyKey: "one", createdAt: stamp });
    assert.equal(result.status, "receipted");
    assert.deepEqual(h.events, ["authorize", "execute", "receipt"]);
    assert.equal(h.calls[0].params.arguments.value, "private");
  } finally { await h.cleanup(); }
});

test("MCP never dispatches denied, forged, unbound or malformed authorization", async () => {
  for (const mutate of [
    (r: any) => { r.validation.decision = "Deny"; },
    (r: any) => { r.validation.decision = "HumanApprovalRequired"; },
    (r: any) => { r.validation.reason_codes = ["EmergencyStopEngaged"]; },
    (r: any) => { r.validation.reason_codes = ["Revoked"]; },
    (r: any) => { r.receipt.action_id = Array(32).fill(1); },
    (r: any) => { r.exochain_finality_height = 0; },
    (r: any) => { r.action_response_attestation.signature.Ed25519[0] ^= 1; },
    (r: any) => { r.action_response_attestation.validator_did = "did:exo:forged"; },
    (r: any) => { delete r.action_response_attestation; },
    (r: any) => { r.validation.valid_until = { physical_ms: 1, logical: 0 }; },
    (_r: any, request: any) => actionResponse({ ...request, subject_signature: { Ed25519: Array(64).fill(8) } }),
  ]) {
    const h = await harness((r, request) => mutate(r, request) ?? r);
    try {
      await assert.rejects(h.proxy().callTool({ name: "write", arguments: {} },
        { idempotencyKey: "one", createdAt: stamp }));
      assert.equal(h.calls.length, 0);
    } finally { await h.cleanup(); }
  }
});

test("concurrent proxies and restart cannot replay an execution idempotency key", async () => {
  const h = await harness();
  try {
    const attempt = () => h.proxy().callTool({ name: "write", arguments: {} },
      { idempotencyKey: "one", createdAt: stamp });
    const results = await Promise.allSettled([attempt(), attempt()]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.equal(h.calls.length, 1);
    await assert.rejects(attempt());
    await assert.rejects(h.proxy().callTool({ name: "different", arguments: { changed: true } },
      { idempotencyKey: "one", createdAt: stamp }));
    assert.equal(h.calls.length, 1);
  } finally { await h.cleanup(); }
});

test("argument mutation during authorization cannot change the executed snapshot", async () => {
  const h = await harness();
  try {
    const args = { value: "approved" };
    h.authorization.prepare = intent => {
      args.value = "altered";
      return prepareAction(intent);
    };
    await h.proxy().callTool({ name: "write", arguments: args },
      { idempotencyKey: "mutation", createdAt: stamp });
    assert.equal(h.calls[0].params.arguments.value, "approved");
  } finally { await h.cleanup(); }
});

test("human cancellation during authorization prevents dispatch", async () => {
  const h = await harness();
  try {
    const controller = new AbortController();
    h.authorization.prepare = intent => { controller.abort(); return prepareAction(intent); };
    await assert.rejects(h.proxy().callTool({ name: "write", arguments: {} },
      { idempotencyKey: "stop", createdAt: stamp, signal: controller.signal }));
    assert.equal(h.calls.length, 0);
  } finally { await h.cleanup(); }
});

test("signer cannot substitute an action and stale authorizations cannot dispatch", async () => {
  const h = await harness();
  try {
    h.authorization.prepare = intent => {
      const prepared = prepareAction(intent);
      prepared.validation.action.tool = "different";
      return prepared;
    };
    await assert.rejects(h.proxy().callTool({ name: "write", arguments: {} },
      { idempotencyKey: "substitution", createdAt: stamp }));
    assert.deepEqual(h.events, []);
    h.authorization.prepare = prepareAction;
    h.authorization.now = () => ({ physical_ms: stamp.physical_ms + 60_000, logical: 0 });
    await assert.rejects(h.proxy().callTool({ name: "write", arguments: {} },
      { idempotencyKey: "stale", createdAt: stamp }));
    assert.equal(h.calls.length, 0);
  } finally { await h.cleanup(); }
});

test("an unresponsive host signer has a deadline and cannot hang or dispatch", { timeout: 500 }, async () => {
  const h = await harness();
  try {
    h.config.requestTimeoutMs = 10;
    h.authorization.prepare = () => new Promise(() => {});
    await assert.rejects(h.proxy().callTool({ name: "write", arguments: {} },
      { idempotencyKey: "signer-timeout", createdAt: stamp }));
    assert.deepEqual(h.events, []);
  } finally { await h.cleanup(); }
});
