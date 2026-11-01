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
import { emitUsageReceipt, requireProductionValidatorTrust } from "./receipt.js";
import { fetchBoundedResponse, parseBoundedJson } from "./http.js";
import { authorizeMcpExecution, checkCancellation, requireHlc, snapshotJson } from "./action-authorization.js";
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
const governedProxies = new WeakSet<object>();

export function isGovernedMcpProxy(value: unknown): value is ReceiptedMcpProxy {
  return typeof value === "object" && value !== null && governedProxies.has(value);
}

export interface ReceiptedMcpProxy {
  callTool(call: McpToolCall, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
}

/** Raised only before a tool was dispatched. Later failures may have external effects. */
export class McpAuthorizationError extends LynkValidationError {
  constructor() {
    super("MCP action was not authorized before dispatch");
    this.name = "McpAuthorizationError";
  }
}

export function createReceiptedMcpProxy(
  config: LlmProxyConfig,
  mcp: McpProxyOptions,
): ReceiptedMcpProxy {
  requireProductionValidatorTrust(config);
  if (!mcp.serverUrl || mcp.serverUrl.trim() === "") {
    throw new LynkConfigurationError("MCP LYNK proxy requires serverUrl");
  }
  if (config.mode === "production" && (!mcp.authorization
    || typeof mcp.authorization.prepare !== "function"
    || typeof mcp.authorization.now !== "function"
    || typeof mcp.authorization.journal?.claim !== "function")) {
    throw new LynkConfigurationError("production MCP requires pre-execution authorization and a durable journal");
  }
  const endpoint = mcp.serverUrl;
  const serverUrl = new URL(endpoint);
  if (serverUrl.username || serverUrl.password || serverUrl.hash
    || (config.mode === "production" && serverUrl.protocol !== "https:")
    || !["http:", "https:"].includes(serverUrl.protocol)) {
    throw new LynkConfigurationError("MCP requires an HTTPS endpoint without embedded credentials or fragment");
  }
  const boundConfig = { ...config };
  const authorization = mcp.authorization ? { ...mcp.authorization } : undefined;
  const proxy: ReceiptedMcpProxy = Object.freeze({
    callTool: (call: McpToolCall, options: PerCallReceiptOptions) =>
      callMcpTool(boundConfig, endpoint, call, options, authorization),
  });
  if (config.mode === "production" && authorization) governedProxies.add(proxy);
  return proxy;
}

async function callMcpTool(
  config: LlmProxyConfig,
  serverUrl: string,
  call: McpToolCall,
  options: PerCallReceiptOptions,
  authorization?: McpProxyOptions["authorization"],
): Promise<ReceiptedResult<unknown>> {
  if (typeof call.name !== "string" || call.name.trim() === "" || call.name.length > 256) {
    throw new LynkValidationError("MCP tools/call requires a tool name");
  }
  if (typeof options.idempotencyKey !== "string" || options.idempotencyKey.trim() === ""
    || options.idempotencyKey.length > 256) {
    throw new LynkValidationError("MCP requires a non-empty idempotency key no longer than 256 characters");
  }
  options = { ...options, createdAt: requireHlc(options.createdAt),
    issuedAt: options.issuedAt ? requireHlc(options.issuedAt) : undefined };
  checkCancellation(options.signal);
  const requestPayload = snapshotJson({
    jsonrpc: "2.0",
    id: options.idempotencyKey,
    method: "tools/call",
    params: {
      name: call.name,
      arguments: call.arguments ?? {},
    },
  }) as { jsonrpc: string; id: string; method: string; params: { name: string; arguments: unknown } };
  if (!isRecord(requestPayload.params.arguments)) {
    throw new LynkValidationError("MCP tool arguments must be a JSON object");
  }
  call = { name: requestPayload.params.name, arguments: requestPayload.params.arguments };
  if (authorization) {
    try { await authorizeMcpExecution(config, authorization, serverUrl, requestPayload, options); }
    catch { throw new McpAuthorizationError(); }
  }
  checkCancellation(options.signal);
  const bounded = await fetchBoundedResponse(
    config,
    serverUrl,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(requestPayload),
      redirect: "error",
      signal: options.signal,
    },
    "MCP tools/call response",
  );
  const { response } = bounded;
  const responsePayload = parseBoundedJson(bounded, "MCP tools/call response");
  if (!response.ok || (isRecord(responsePayload) && (responsePayload.error !== undefined
    || (isRecord(responsePayload.result) && responsePayload.result.isError === true)))) {
    return emitMcpFailureReceipt(config, call, requestPayload, response.status, options);
  }
  if (!isValidMcpToolResult(responsePayload, requestPayload.id)) {
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

function isValidMcpToolResult(payload: unknown, expectedId: string): payload is JsonRecord {
  if (!isRecord(payload)) {
    return false;
  }
  if (
    payload.jsonrpc !== "2.0"
    || !Object.prototype.hasOwnProperty.call(payload, "id")
    || payload.id !== expectedId
    || Object.prototype.hasOwnProperty.call(payload, "error")
  ) {
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
