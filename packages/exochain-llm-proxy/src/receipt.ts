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

import { assertNoForbiddenReceiptMaterial, LynkConfigurationError } from "./evidence.js";
import type {
  FetchLike,
  LlmProxyConfig,
  ReceiptEmissionResult,
  ReceiptIntent,
  ReceiptPending,
} from "./types.js";

export class ReceiptEmissionError extends Error {
  readonly statusCode?: number;
  readonly idempotencyKeyHash: string;
  readonly receiptIntent: ReceiptIntent;

  constructor(message: string, idempotencyKeyHash: string, receiptIntent: ReceiptIntent, statusCode?: number) {
    super(message);
    this.name = "ReceiptEmissionError";
    this.statusCode = statusCode;
    this.idempotencyKeyHash = idempotencyKeyHash;
    this.receiptIntent = receiptIntent;
  }
}

export function receiptPendingFromError(error: ReceiptEmissionError): ReceiptPending {
  return {
    status: "receipt_pending",
    idempotencyKeyHash: error.idempotencyKeyHash,
    receiptIntent: error.receiptIntent,
  };
}

export async function emitUsageReceipt(
  config: LlmProxyConfig,
  receiptIntent: ReceiptIntent,
): Promise<ReceiptEmissionResult> {
  assertNoForbiddenReceiptMaterial(receiptIntent);
  const fetchImpl = resolveFetch(config.fetch);
  const endpoint = `${config.gatewayUrl.replace(/\/+$/, "")}/api/v1/avc/llm-usage/receipts/emit`;
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(receiptIntent),
  });
  if (!response.ok) {
    throw new ReceiptEmissionError(
      "EXOCHAIN LYNK receipt emission failed",
      receiptIntent.llm_usage_evidence.evidence.idempotency_key_hash,
      receiptIntent,
      response.status,
    );
  }
  return (await response.json()) as ReceiptEmissionResult;
}

export async function resolveReceiptPending(
  config: LlmProxyConfig,
  pending: ReceiptPending,
): Promise<ReceiptEmissionResult> {
  return emitUsageReceipt(config, pending.receiptIntent);
}

export function resolveFetch(fetchImpl?: FetchLike): FetchLike {
  if (fetchImpl) {
    return fetchImpl;
  }
  if (globalThis.fetch) {
    return globalThis.fetch.bind(globalThis) as FetchLike;
  }
  throw new LynkConfigurationError("LYNK proxy requires fetch");
}
