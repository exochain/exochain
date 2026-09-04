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
