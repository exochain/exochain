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

import {
  buildLlmUsageReceiptIntent,
  hashProviderPayload,
  LynkConfigurationError,
  LynkValidationError,
  maybeStoreExternalPayloads,
} from "./evidence.js";
import { releaseWithReceipt } from "./delivery.js";
import { emitUsageReceipt, resolveFetch } from "./receipt.js";
import type {
  LlmProxyConfig,
  McpProxyOptions,
  McpToolCall,
  PerCallReceiptOptions,
  ProviderFailure,
  ProviderUsageMetrics,
  ReceiptedResult,
  UsageContext,
} from "./types.js";

type JsonRecord = Record<string, unknown>;

export interface ReceiptedMcpProxy {
  callTool(call: McpToolCall, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
}

export function createReceiptedMcpProxy(
  config: LlmProxyConfig,
  mcp: McpProxyOptions,
): ReceiptedMcpProxy {
  if (!mcp.serverUrl || mcp.serverUrl.trim() === "") {
    throw new LynkConfigurationError("MCP LYNK proxy requires serverUrl");
  }
  return {
    callTool: (call, options) => callMcpTool(config, mcp.serverUrl as string, call, options),
  };
}

async function callMcpTool(
  config: LlmProxyConfig,
  serverUrl: string,
  call: McpToolCall,
  options: PerCallReceiptOptions,
): Promise<ReceiptedResult<unknown>> {
  if (!call.name || call.name.trim() === "") {
    throw new LynkValidationError("MCP tools/call requires a tool name");
  }
  const requestPayload = {
    jsonrpc: "2.0",
    id: options.idempotencyKey,
    method: "tools/call",
    params: {
      name: call.name,
      arguments: call.arguments ?? {},
    },
  };
  const response = await resolveFetch(config.fetch)(serverUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(requestPayload),
  });
  const responsePayload = (await response.json()) as unknown;
  if (!response.ok || (isRecord(responsePayload) && responsePayload.error !== undefined)) {
    return emitMcpFailureReceipt(config, call, requestPayload, response.status, options);
  }
  if (!isValidMcpToolResult(responsePayload)) {
    throw new LynkValidationError("MCP tools/call response was malformed or untrusted");
  }
  const encryptedPayloadRefs = await maybeStoreExternalPayloads(config, [
    { payloadKind: "mcp_tool_call", payload: requestPayload },
    { payloadKind: "mcp_tool_result", payload: responsePayload },
  ]);
  const context = mcpUsageContext(
    call,
    requestPayload,
    responsePayload,
    zeroUsage(true),
    options,
    encryptedPayloadRefs,
  );
  const receiptIntent = await buildLlmUsageReceiptIntent(config, context);
  return releaseWithReceipt(config, receiptIntent, responsePayload);
}

async function emitMcpFailureReceipt(
  config: LlmProxyConfig,
  call: McpToolCall,
  requestPayload: JsonRecord,
  providerStatus: number,
  options: PerCallReceiptOptions,
): Promise<ProviderFailure> {
  const context = mcpUsageContext(
    call,
    requestPayload,
    { provider_status: providerStatus },
    zeroUsage(false),
    options,
    [],
  );
  const receiptIntent = await buildLlmUsageReceiptIntent(config, context);
  const receipt = await emitUsageReceipt(config, receiptIntent).catch(() => undefined);
  return {
    status: "provider_error",
    providerStatus,
    receipt,
    receiptIntent,
  };
}

function mcpUsageContext(
  call: McpToolCall,
  requestPayload: JsonRecord,
  responsePayload: unknown,
  usage: ProviderUsageMetrics,
  options: PerCallReceiptOptions,
  encryptedPayloadRefs: UsageContext["encryptedPayloadRefs"],
): UsageContext {
  return {
    provider: "mcp",
    providerEndpoint: "tools/call",
    modelId: call.name,
    requestPayload,
    responsePayload,
    toolCallPayload: requestPayload,
    toolResultPayload: responsePayload,
    idempotencyKey: options.idempotencyKey,
    actionId: options.actionId ?? hashProviderPayload(["mcp", call.name, options.idempotencyKey]),
    usage,
    createdAt: options.createdAt,
    issuedAt: options.issuedAt ?? options.createdAt,
    encryptedPayloadRefs,
  };
}

function isValidMcpToolResult(payload: unknown): payload is JsonRecord {
  if (!isRecord(payload)) {
    return false;
  }
  if (payload.jsonrpc !== undefined && payload.jsonrpc !== "2.0") {
    return false;
  }
  const result = payload.result;
  return isRecord(result) && (Array.isArray(result.content) || result.structuredContent !== undefined);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function zeroUsage(usageComplete: boolean): ProviderUsageMetrics {
  return {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    usage_complete: usageComplete,
  };
}
