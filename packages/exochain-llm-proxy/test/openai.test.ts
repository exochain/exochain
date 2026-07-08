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
  LynkValidationError,
  createReceiptedOpenAIClient,
  createReceiptedOpenAIProxy,
  hashProviderPayload,
  parseSseStream,
  stableStringify,
  type FetchLike,
  type LlmProxyConfig,
  type ReceiptIntent,
  usageFromChatCompletions,
  usageFromResponses,
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

function textResponse(value: string, status = 200): Response {
  return new Response(value, {
    status,
    headers: { "content-type": "text/event-stream" },
  });
}

function fakeFetch(
  receiptBodies: ReceiptIntent[],
  provider: (url: string, body: unknown) => Response,
  receiptStatus = 200,
): FetchLike {
  return async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
      receiptBodies.push(body as ReceiptIntent);
      return jsonResponse({ receipt_hash: "receipt-1", receipt: { ok: true } }, receiptStatus);
    }
    return provider(url, body);
  };
}

test("responses success emits receipt and releases output", async () => {
  const receipts: ReceiptIntent[] = [];
  const providerPayload = {
    id: "resp_1",
    model: "gpt-4.1-mini",
    output: [{ type: "message", content: [{ type: "output_text", text: "secret-output" }] }],
    usage: {
      input_tokens: 12,
      input_tokens_details: { cached_tokens: 3 },
      output_tokens: 5,
      output_tokens_details: { reasoning_tokens: 2 },
      total_tokens: 17,
    },
  };
  const client = createReceiptedOpenAIClient(
    baseConfig(
      fakeFetch(receipts, (url) => {
        assert.equal(url, "https://openai.test/v1/responses");
        return jsonResponse(providerPayload);
      }),
    ),
    { openAIBaseUrl: "https://openai.test", apiKey: "sk-secret" },
  );

  const result = await client.responses.create(
    { model: "gpt-4.1-mini", input: "secret-prompt" },
    { idempotencyKey: "idem-1", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.provider_endpoint, "responses");
  assert.deepEqual(receipts[0]?.llm_usage_evidence.evidence.usage, {
    input_tokens: 12,
    output_tokens: 5,
    total_tokens: 17,
    cached_input_tokens: 3,
    reasoning_tokens: 2,
    usage_complete: true,
  });
  const serialized = stableStringify(receipts[0]);
  assert.equal(serialized.includes("secret-prompt"), false);
  assert.equal(serialized.includes("secret-output"), false);
  assert.equal(serialized.includes("sk-secret"), false);
});

test("chat completions success maps usage fields", async () => {
  const receipts: ReceiptIntent[] = [];
  const client = createReceiptedOpenAIClient(
    baseConfig(
      fakeFetch(receipts, (url) => {
        assert.equal(url, "https://openai.test/v1/chat/completions");
        return jsonResponse({
          id: "chatcmpl_1",
          choices: [{ message: { role: "assistant", content: "secret-output" } }],
          usage: {
            prompt_tokens: 20,
            prompt_tokens_details: { cached_tokens: 4 },
            completion_tokens: 9,
            completion_tokens_details: { reasoning_tokens: 1 },
            total_tokens: 29,
          },
        });
      }),
    ),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.chat.completions.create(
    { model: "gpt-4.1-mini", messages: [{ role: "user", content: "secret-prompt" }] },
    { idempotencyKey: "idem-2", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.deepEqual(receipts[0]?.llm_usage_evidence.evidence.usage, {
    input_tokens: 20,
    output_tokens: 9,
    total_tokens: 29,
    cached_input_tokens: 4,
    reasoning_tokens: 1,
    usage_complete: true,
  });
});

test("OpenAI proxy alias omits bearer header when no API key is configured", async () => {
  const receipts: ReceiptIntent[] = [];
  let providerHeaders: HeadersInit | undefined;
  const client = createReceiptedOpenAIProxy(
    baseConfig(
      fakeFetch(receipts, (_url, _body) => {
        return jsonResponse({
          id: "resp_alias",
          output: [{ text: "placeholder output" }],
          input_tokens: 2,
          output_tokens: 3,
          total_tokens: 5,
        });
      }),
    ),
    { openAIBaseUrl: "https://openai.test/" },
  );
  const configFetch = baseConfig(async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
      receipts.push(body as ReceiptIntent);
      return jsonResponse({ receipt_hash: "receipt-alias" });
    }
    providerHeaders = init?.headers;
    assert.equal(url, "https://openai.test/v1/responses");
    return jsonResponse({
      id: "resp_alias",
      output: [{ text: "placeholder output" }],
      input_tokens: 2,
      output_tokens: 3,
      total_tokens: 5,
    });
  });
  const aliasClient = createReceiptedOpenAIProxy(configFetch, {
    openAIBaseUrl: "https://openai.test/",
  });

  const result = await aliasClient.responses.create(
    { input: "placeholder" },
    { idempotencyKey: "idem-alias", createdAt: stamp, issuedAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0]?.llm_usage_evidence.evidence.model_id, "unknown");
  assert.deepEqual(providerHeaders, { "content-type": "application/json" });
  assert.equal(client.chat.completions.create instanceof Function, true);
});

test("provider failure emits failure receipt intent without provider body leak", async () => {
  const receipts: ReceiptIntent[] = [];
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch(receipts, () => jsonResponse({ error: "very-secret-provider-error" }, 429))),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.responses.create(
    { model: "gpt-4.1-mini", input: "secret-prompt" },
    { idempotencyKey: "idem-3", createdAt: stamp },
  );

  assert.equal(result.status, "provider_error");
  assert.equal(result.providerStatus, 429);
  assert.equal(stableStringify(result.receiptIntent).includes("very-secret-provider-error"), false);
  assert.equal(receipts.length, 1);
});

test("provider success plus receipt failure withholds output as receipt pending", async () => {
  const receipts: ReceiptIntent[] = [];
  const client = createReceiptedOpenAIClient(
    baseConfig(
      fakeFetch(
        receipts,
        () =>
          jsonResponse({
            id: "resp_2",
            model: "gpt-4.1-mini",
            output: [{ text: "secret-output" }],
            usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
          }),
        503,
      ),
    ),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.responses.create(
    { model: "gpt-4.1-mini", input: "secret-prompt" },
    { idempotencyKey: "idem-4", createdAt: stamp },
  );

  assert.equal(result.status, "receipt_pending");
  assert.equal("output" in result, false);
  assert.equal(receipts.length, 1);
});

test("streaming chat without final usage chunk records incomplete usage", async () => {
  const receipts: ReceiptIntent[] = [];
  const stream = [
    'data: {"id":"chunk_1","choices":[{"delta":{"content":"secret-output"}}],"usage":null}',
    "data: [DONE]",
    "",
  ].join("\n\n");
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch(receipts, () => textResponse(stream))),
    { openAIBaseUrl: "https://openai.test" },
  );

  const result = await client.chat.completions.create(
    {
      model: "gpt-4.1-mini",
      messages: [{ role: "user", content: "secret-prompt" }],
      stream: true,
      stream_options: { include_usage: true },
    },
    { idempotencyKey: "idem-5", createdAt: stamp },
  );

  assert.equal(result.status, "receipted");
  assert.deepEqual(receipts[0]?.llm_usage_evidence.evidence.usage, {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    usage_complete: false,
  });
});

test("requireCompleteUsage rejects interrupted streaming usage", async () => {
  const receipts: ReceiptIntent[] = [];
  const stream = ['data: {"id":"chunk_1","choices":[{"delta":{"content":"placeholder"}}]}', ""].join(
    "\n\n",
  );
  const config = baseConfig(fakeFetch(receipts, () => textResponse(stream)));
  config.requireCompleteUsage = true;
  const client = createReceiptedOpenAIClient(config, { openAIBaseUrl: "https://openai.test" });

  await assert.rejects(
    () =>
      client.chat.completions.create(
        {
          model: "gpt-4.1-mini",
          messages: [{ role: "user", content: "placeholder" }],
          stream: true,
        },
        { idempotencyKey: "idem-6", createdAt: stamp },
      ),
    LynkValidationError,
  );
  assert.equal(receipts.length, 0);
});

test("OpenAI usage rejects non-integer and negative counters", async () => {
  const clientWithFractionalUsage = createReceiptedOpenAIClient(
    baseConfig(
      fakeFetch([], () =>
        jsonResponse({
          id: "resp_fractional",
          usage: { input_tokens: 1.25, output_tokens: 1, total_tokens: 3 },
        }),
      ),
    ),
    { openAIBaseUrl: "https://openai.test" },
  );
  await assert.rejects(
    () =>
      clientWithFractionalUsage.responses.create(
        { model: "gpt-4.1-mini", input: "placeholder" },
        { idempotencyKey: "idem-7", createdAt: stamp },
      ),
    LynkValidationError,
  );

  const clientWithNegativeUsage = createReceiptedOpenAIClient(
    baseConfig(
      fakeFetch([], () =>
        jsonResponse({
          id: "chat_negative",
          usage: { prompt_tokens: -1, completion_tokens: 1, total_tokens: 1 },
        }),
      ),
    ),
    { openAIBaseUrl: "https://openai.test" },
  );
  await assert.rejects(
    () =>
      clientWithNegativeUsage.chat.completions.create(
        { model: "gpt-4.1-mini", messages: [{ role: "user", content: "placeholder" }] },
        { idempotencyKey: "idem-8", createdAt: stamp },
      ),
    LynkValidationError,
  );
});

test("production rejects development unreceipted output flag", () => {
  const config = baseConfig(async () => jsonResponse({}));
  config.allowUnreceiptedOutputForDevelopment = true;

  assert.throws(
    () => createReceiptedOpenAIClient(config, { openAIBaseUrl: "https://openai.test" }),
    LynkValidationError,
  );
});

test("malformed streaming SSE is rejected before receipt emission", async () => {
  const receipts: ReceiptIntent[] = [];
  const client = createReceiptedOpenAIClient(
    baseConfig(fakeFetch(receipts, () => textResponse("data: {not json}\n\n"))),
    { openAIBaseUrl: "https://openai.test" },
  );

  await assert.rejects(
    () =>
      client.responses.create(
        { model: "gpt-4.1-mini", input: "placeholder", stream: true },
        { idempotencyKey: "idem-9", createdAt: stamp },
      ),
    SyntaxError,
  );
  assert.equal(receipts.length, 0);
});

test("OpenAI usage parser baselines cover stream and incomplete payload branches", () => {
  assert.deepEqual(usageFromResponses("not-a-record"), {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    usage_complete: false,
  });
  assert.deepEqual(
    usageFromResponses({
      object: "openai_stream",
      usage: {
        input_tokens: 4,
        input_tokens_details: { cached_tokens: null },
        output_tokens: 1,
        output_tokens_details: { reasoning_tokens: null },
      },
    }),
    {
      input_tokens: 4,
      output_tokens: 1,
      total_tokens: 5,
      cached_input_tokens: undefined,
      reasoning_tokens: undefined,
      usage_complete: true,
    },
  );
  assert.deepEqual(usageFromChatCompletions("not-a-record"), {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    usage_complete: false,
  });
  assert.deepEqual(
    usageFromChatCompletions({
      object: "openai_stream",
      usage_complete: true,
      usage: {
        prompt_tokens: 2,
        prompt_tokens_details: {},
        completion_tokens: 2,
        completion_tokens_details: {},
      },
    }),
    {
      input_tokens: 2,
      output_tokens: 2,
      total_tokens: 4,
      cached_input_tokens: undefined,
      reasoning_tokens: undefined,
      usage_complete: true,
    },
  );
  assert.deepEqual(parseSseStream('event: ignored\ndata: [DONE]\ndata: {"usage":{"input_tokens":1,"output_tokens":1}}\n'), {
    object: "openai_stream",
    events: [{ usage: { input_tokens: 1, output_tokens: 1 } }],
    usage: { input_tokens: 1, output_tokens: 1 },
    usage_complete: true,
  });
});
