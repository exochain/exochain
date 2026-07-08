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

import { buildLlmUsageReceiptIntent, maybeStoreExternalPayloads } from "./evidence.js";
import { releaseWithReceipt } from "./delivery.js";
import { emitUsageReceipt } from "./receipt.js";
import { hashProviderPayload, LynkValidationError } from "./evidence.js";
import type {
  LlmProxyConfig,
  OpenAIProxyOptions,
  PerCallReceiptOptions,
  ProviderFailure,
  ProviderUsageMetrics,
  ReceiptedResult,
  UsageContext,
} from "./types.js";
import { resolveFetch } from "./receipt.js";

type JsonRecord = Record<string, unknown>;

export interface ReceiptedOpenAIClient {
  responses: {
    create(body: JsonRecord, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
  };
  chat: {
    completions: {
      create(body: JsonRecord, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
    };
  };
}

export function createReceiptedOpenAIClient(
  config: LlmProxyConfig,
  openAI: OpenAIProxyOptions,
): ReceiptedOpenAIClient {
  assertProductionDevelopmentFlag(config);
  return {
    responses: {
      create: (body, options) =>
        callOpenAIEndpoint(config, openAI, "responses", "/v1/responses", body, options),
    },
    chat: {
      completions: {
        create: (body, options) =>
          callOpenAIEndpoint(
            config,
            openAI,
            "chat_completions",
            "/v1/chat/completions",
            body,
            options,
          ),
      },
    },
  };
}

export function createReceiptedOpenAIProxy(
  config: LlmProxyConfig,
  openAI: OpenAIProxyOptions,
): ReceiptedOpenAIClient {
  return createReceiptedOpenAIClient(config, openAI);
}

async function callOpenAIEndpoint(
  config: LlmProxyConfig,
  openAI: OpenAIProxyOptions,
  endpointName: "responses" | "chat_completions",
  path: string,
  body: JsonRecord,
  options: PerCallReceiptOptions,
): Promise<ReceiptedResult<unknown>> {
  const fetchImpl = resolveFetch(config.fetch);
  const response = await fetchImpl(`${openAI.openAIBaseUrl.replace(/\/+$/, "")}${path}`, {
    method: "POST",
    headers: openAI.apiKey
      ? {
          "content-type": "application/json",
          authorization: `Bearer ${openAI.apiKey}`,
        }
      : {
          "content-type": "application/json",
        },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    return emitProviderFailureReceipt(config, endpointName, body, response.status, options);
  }
  const responsePayload = await parseOpenAIResponse(response, body);
  const usage =
    endpointName === "responses"
      ? usageFromResponses(responsePayload)
      : usageFromChatCompletions(responsePayload);
  if (config.requireCompleteUsage === true && usage.usage_complete !== true) {
    throw new LynkValidationError("OpenAI endpoint policy requires complete usage fields");
  }
  const encryptedPayloadRefs = await maybeStoreExternalPayloads(config, [
    { payloadKind: "openai_request", payload: body },
    { payloadKind: "openai_response", payload: responsePayload },
  ]);
  const context = usageContext(endpointName, body, responsePayload, usage, options, encryptedPayloadRefs);
  const receiptIntent = await buildLlmUsageReceiptIntent(config, context);
  return releaseWithReceipt(config, receiptIntent, responsePayload);
}

async function emitProviderFailureReceipt(
  config: LlmProxyConfig,
  endpointName: "responses" | "chat_completions",
  body: JsonRecord,
  providerStatus: number,
  options: PerCallReceiptOptions,
): Promise<ProviderFailure> {
  const context = usageContext(endpointName, body, { provider_status: providerStatus }, zeroUsage(false), options, []);
  const receiptIntent = await buildLlmUsageReceiptIntent(config, context);
  const receipt = await emitUsageReceipt(config, receiptIntent).catch(() => undefined);
  return {
    status: "provider_error",
    providerStatus,
    receipt,
    receiptIntent,
  };
}

async function parseOpenAIResponse(response: Response, requestBody: JsonRecord): Promise<unknown> {
  if (requestBody.stream === true) {
    const text = await response.text();
    return parseSseStream(text);
  }
  return response.json();
}

export function parseSseStream(text: string): JsonRecord {
  const events: unknown[] = [];
  let finalUsage: unknown;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("data:")) {
      continue;
    }
    const data = line.slice("data:".length).trim();
    if (data === "[DONE]") {
      continue;
    }
    const parsed = JSON.parse(data) as JsonRecord;
    events.push(parsed);
    if (isRecord(parsed.usage)) {
      finalUsage = parsed.usage;
    }
  }
  return {
    object: "openai_stream",
    events,
    usage: finalUsage,
    usage_complete: finalUsage !== undefined,
  };
}

export function usageFromResponses(payload: unknown): ProviderUsageMetrics {
  if (!isRecord(payload)) {
    return zeroUsage(false);
  }
  if (payload.object === "openai_stream") {
    return usageFromResponses(payload.usage);
  }
  const usage = isRecord(payload.usage) ? payload.usage : payload;
  const inputTokens = integerField(usage, "input_tokens", 0);
  const outputTokens = integerField(usage, "output_tokens", 0);
  const totalTokens = integerField(usage, "total_tokens", inputTokens + outputTokens);
  const inputDetails = isRecord(usage.input_tokens_details) ? usage.input_tokens_details : {};
  const outputDetails = isRecord(usage.output_tokens_details) ? usage.output_tokens_details : {};
  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
    cached_input_tokens: optionalIntegerField(inputDetails, "cached_tokens"),
    reasoning_tokens: optionalIntegerField(outputDetails, "reasoning_tokens"),
    usage_complete: inputTokens + outputTokens > 0 || totalTokens > 0,
  };
}

export function usageFromChatCompletions(payload: unknown): ProviderUsageMetrics {
  if (!isRecord(payload)) {
    return zeroUsage(false);
  }
  if (payload.object === "openai_stream") {
    if (payload.usage_complete !== true) {
      return zeroUsage(false);
    }
    return usageFromChatCompletions(payload.usage);
  }
  const usage = isRecord(payload.usage) ? payload.usage : payload;
  const inputTokens = integerField(usage, "prompt_tokens", 0);
  const outputTokens = integerField(usage, "completion_tokens", 0);
  const totalTokens = integerField(usage, "total_tokens", inputTokens + outputTokens);
  const inputDetails = isRecord(usage.prompt_tokens_details) ? usage.prompt_tokens_details : {};
  const outputDetails = isRecord(usage.completion_tokens_details) ? usage.completion_tokens_details : {};
  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
    cached_input_tokens: optionalIntegerField(inputDetails, "cached_tokens"),
    reasoning_tokens: optionalIntegerField(outputDetails, "reasoning_tokens"),
    usage_complete: inputTokens + outputTokens > 0 || totalTokens > 0,
  };
}

function usageContext(
  endpointName: "responses" | "chat_completions",
  requestPayload: JsonRecord,
  responsePayload: unknown,
  usage: ProviderUsageMetrics,
  options: PerCallReceiptOptions,
  encryptedPayloadRefs: UsageContext["encryptedPayloadRefs"],
): UsageContext {
  return {
    provider: "openai",
    providerEndpoint: endpointName,
    modelId: typeof requestPayload.model === "string" ? requestPayload.model : "unknown",
    requestPayload,
    responsePayload,
    providerRequestId: isRecord(responsePayload) && typeof responsePayload.id === "string" ? responsePayload.id : undefined,
    sessionId: options.sessionId,
    idempotencyKey: options.idempotencyKey,
    actionId: options.actionId ?? hashProviderPayload(["openai", endpointName, options.idempotencyKey]),
    usage,
    createdAt: options.createdAt,
    issuedAt: options.issuedAt ?? options.createdAt,
    encryptedPayloadRefs,
  };
}

function zeroUsage(usageComplete: boolean): ProviderUsageMetrics {
  return {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    usage_complete: usageComplete,
  };
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function integerField(record: JsonRecord, name: string, fallback: number): number {
  const value = record[name];
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new LynkValidationError(
      `OpenAI usage field ${name} must be a non-negative integer`,
    );
  }
  return value;
}

function optionalIntegerField(record: JsonRecord, name: string): number | undefined {
  const value = record[name];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new LynkValidationError(
      `OpenAI usage field ${name} must be a non-negative integer`,
    );
  }
  return value;
}

function assertProductionDevelopmentFlag(config: LlmProxyConfig): void {
  if (config.mode === "production" && config.allowUnreceiptedOutputForDevelopment === true) {
    throw new LynkValidationError(
      "allowUnreceiptedOutputForDevelopment is forbidden in production",
    );
  }
}
