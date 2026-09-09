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
import { readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";
import { LynkConfigurationError, LynkValidationError } from "../src/evidence.js";
import { fetchBoundedResponse, parseBoundedJson } from "../src/http.js";
import type { FetchLike, LlmProxyConfig } from "../src/types.js";

function policy(
  fetchImpl: FetchLike,
  maxResponseBytes = 8,
  requestTimeoutMs = 1_000,
): LlmProxyConfig {
  return {
    mode: "production",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    custodyPolicyHash: "0".repeat(64),
    storageMode: "receipt_minimized",
    validation: {},
    subjectSignature: "subject-signature",
    adapterSignature: "adapter-signature",
    fetch: fetchImpl,
    maxResponseBytes,
    requestTimeoutMs,
  };
}

function streamedResponse(
  chunks: readonly string[],
  init?: ResponseInit,
  close = true,
): Response {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(chunk));
        }
        if (close) controller.close();
      },
    }),
    init,
  );
}

class LyingUint8Array extends Uint8Array {
  override get byteLength(): number {
    return 0;
  }

  override get length(): number {
    return 0;
  }

  override [Symbol.iterator]() {
    return new Uint8Array()[Symbol.iterator]();
  }
}

test("bounded reader does not retain a collection of per-fragment allocations", () => {
  const source = ts.createSourceFile(
    "http.ts",
    readFileSync(new URL("../../src/http.ts", import.meta.url), "utf8"),
    ts.ScriptTarget.ES2022,
    true,
  );
  const reader = source.statements.find(
    (node): node is ts.FunctionDeclaration =>
      ts.isFunctionDeclaration(node) && node.name?.text === "readBoundedBody",
  );
  assert.ok(reader?.body, "the shared bounded reader must be inspected");
  const fragmentCollections: string[] = [];
  function inspect(node: ts.Node): void {
    if (
      ts.isArrayLiteralExpression(node)
      || (ts.isNewExpression(node)
        && ts.isIdentifier(node.expression)
        && ["Array", "Map", "Set"].includes(node.expression.text))
      || (ts.isCallExpression(node)
        && ts.isPropertyAccessExpression(node.expression)
        && node.expression.name.text === "push")
    ) {
      fragmentCollections.push(node.getText(source));
    }
    ts.forEachChild(node, inspect);
  }
  inspect(reader.body);
  assert.deepEqual(
    fragmentCollections,
    [],
    "payload-byte accounting must not retain an independently growing fragment collection",
  );
});

test("bounded fetch preserves exact bytes across small and empty fragments", async () => {
  const result = await fetchBoundedResponse(
    policy(async () => streamedResponse(["", "0", "", "1", "2", "", "3", "4", "5", "", "6", "7", ""])),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.text, "01234567");
  assert.deepEqual([...result.body], [48, 49, 50, 51, 52, 53, 54, 55]);
  assert.ok(result.body.buffer.byteLength <= 8, "backing capacity must stay inside the byte budget");
});

test("bounded fetch accepts an empty-fragment-only body without backing storage", async () => {
  const result = await fetchBoundedResponse(
    policy(async () => streamedResponse(["", "", ""])),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.text, "");
  assert.equal(result.body.byteLength, 0);
  assert.equal(result.body.buffer.byteLength, 0);
});

test("bounded fetch preserves many benign one-byte fragments", async () => {
  const text = "0123456789abcdef".repeat(16);
  const result = await fetchBoundedResponse(
    policy(async () => streamedResponse([...text].flatMap((byte) => ["", byte])), text.length),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.text, text);
  assert.deepEqual(result.body, new TextEncoder().encode(text));
  assert.ok(result.body.buffer.byteLength <= text.length);
});

test("bounded fetch preserves earlier bytes when contiguous storage grows", async () => {
  const chunks = ["a".repeat(4096), "b".repeat(4096), "c"];
  const result = await fetchBoundedResponse(
    policy(async () => streamedResponse(chunks), 9000),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.text, chunks.join(""));
  assert.deepEqual(result.body, new TextEncoder().encode(chunks.join("")));
  assert.equal(result.body.byteLength, 8193);
  assert.ok(result.body.buffer.byteLength <= 9000);
});

test("bounded fetch snapshots a reused mutable fragment before the next read", async () => {
  const shared = new LyingUint8Array(1);
  let index = 0;
  const response = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index === 4) {
        controller.close();
        return;
      }
      shared[0] = 65 + index;
      index += 1;
      controller.enqueue(shared);
    },
  }, { highWaterMark: 0 }));
  const result = await fetchBoundedResponse(
    policy(async () => response),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  shared.fill(90);
  assert.equal(result.text, "ABCD");
  assert.deepEqual([...result.body], [65, 66, 67, 68]);
});

test("bounded fetch accepts the exact byte limit despite a dishonest low Content-Length", async () => {
  const fetchImpl: FetchLike = async () =>
    streamedResponse(["1234", "5678"], { headers: { "content-length": "1" } });

  const result = await fetchBoundedResponse(
    policy(fetchImpl),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.text, "12345678");
  assert.equal(result.body.byteLength, 8);
});

test("bounded fetch rejects chunked limit-plus-one without Content-Length", async () => {
  const fetchImpl: FetchLike = async () => streamedResponse(["12345678", "9"]);

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(fetchImpl),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response exceeds 8 bytes");
      return true;
    },
  );
});

test("bounded fetch rejects an oversized declared length before collecting the body", async () => {
  const fetchImpl: FetchLike = async () =>
    streamedResponse([], { headers: { "content-length": "9" } });

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(fetchImpl),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response Content-Length exceeds 8 bytes");
      return true;
    },
  );
});

test("declared-length rejection suppresses an underlying body-cancellation failure", async () => {
  const response = new Response(
    new ReadableStream<Uint8Array>({
      cancel() {
        return Promise.reject(new Error("raw cancellation detail"));
      },
    }),
    { headers: { "content-length": "9" } },
  );

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(async () => response),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    /provider response Content-Length exceeds 8 bytes/,
  );
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
});

test("bounded fetch enforces one deadline through a stalled response body", async () => {
  const fetchImpl: FetchLike = async () => streamedResponse(["{"], undefined, false);

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(fetchImpl, 8, 25),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response timed out after 25 ms");
      return true;
    },
  );
});

test("bounded fetch rejects invalid limits before invoking fetch", async () => {
  let calls = 0;
  const fetchImpl: FetchLike = async () => {
    calls += 1;
    return new Response("{}");
  };
  for (const [field, value] of [
    ["maxResponseBytes", 0],
    ["maxResponseBytes", 1.5],
    ["maxResponseBytes", Number.MAX_SAFE_INTEGER],
    ["requestTimeoutMs", 0],
    ["requestTimeoutMs", 1.5],
    ["requestTimeoutMs", Number.MAX_SAFE_INTEGER],
  ] as const) {
    const config = policy(fetchImpl);
    config[field] = value;
    await assert.rejects(
      () =>
        fetchBoundedResponse(
          config,
          "https://provider.test",
          { method: "GET" },
          "provider response",
        ),
      LynkConfigurationError,
    );
  }
  assert.equal(calls, 0);
});

test("bounded fetch applies defaults and accepts an empty body", async () => {
  const config = policy(async () => new Response(null));
  delete config.maxResponseBytes;
  delete config.requestTimeoutMs;

  const result = await fetchBoundedResponse(
    config,
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.body.byteLength, 0);
  assert.equal(result.text, "");
});

test("bounded JSON parsing rejects malformed response text without echoing it", async () => {
  const result = await fetchBoundedResponse(
    policy(async () => streamedResponse(["secret-not-json"]), 64),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.throws(
    () => parseBoundedJson(result, "provider response"),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response was not valid JSON");
      assert.equal(error.message.includes("secret-not-json"), false);
      return true;
    },
  );
});

test("bounded fetch rejects a non-byte stream chunk", async () => {
  const response = {
    headers: new Headers(),
    body: new ReadableStream<unknown>({
      start(controller) {
        controller.enqueue("not-bytes");
        controller.close();
      },
      cancel() {
        return Promise.reject(new Error("raw cancellation detail"));
      },
    }),
  } as unknown as Response;

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(async () => response),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response returned a non-byte response chunk");
      return true;
    },
  );
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
});

test("bounded fetch measures Uint8Array subclasses by their intrinsic byte length", async () => {
  const chunk = new LyingUint8Array(9);
  chunk.fill(65);
  const response = {
    headers: new Headers(),
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk);
        controller.close();
      },
    }),
  } as unknown as Response;

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(async () => response),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response exceeds 8 bytes");
      return true;
    },
  );
});

test("bounded fetch copies exact-limit Uint8Array subclasses through intrinsic bytes", async () => {
  const chunk = new LyingUint8Array(8);
  chunk.fill(65);
  const response = {
    headers: new Headers(),
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk);
        controller.close();
      },
    }),
  } as unknown as Response;

  const result = await fetchBoundedResponse(
    policy(async () => response),
    "https://provider.test",
    { method: "GET" },
    "provider response",
  );

  assert.equal(result.body.byteLength, 8);
  assert.equal(result.text, "AAAAAAAA");
});

test("bounded fetch normalizes a fetch rejection caused by its deadline", async () => {
  const fetchImpl: FetchLike = async (_input, init) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("raw abort detail")), {
        once: true,
      });
    });

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(fetchImpl, 8, 25),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response timed out after 25 ms");
      assert.equal(error.message.includes("raw abort detail"), false);
      return true;
    },
  );
});

test("bounded fetch suppresses cancellation failures while reporting the size violation", async () => {
  const encoder = new TextEncoder();
  const response = new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("123456789"));
      },
      cancel() {
        return Promise.reject(new Error("raw cancellation detail"));
      },
    }),
  );

  await assert.rejects(
    () =>
      fetchBoundedResponse(
        policy(async () => response),
        "https://provider.test",
        { method: "GET" },
        "provider response",
      ),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "provider response exceeds 8 bytes");
      return true;
    },
  );
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
});

test("every provider and receipt response passes through the shared bounded reader", () => {
  for (const file of ["openai.ts", "mcp.ts", "receipt.ts"]) {
    const source = readFileSync(new URL(`../../src/${file}`, import.meta.url), "utf8");
    assert.match(source, /fetchBoundedResponse/);
    assert.doesNotMatch(source, /response\.(?:json|text)\s*\(/);
  }
});
