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

export {
  AVC_SCHEMA_VERSION,
  LYNK_EVIDENCE_DOMAIN,
  LynkConfigurationError,
  LynkValidationError,
  ZERO_HASH,
  assertNoForbiddenReceiptMaterial,
  buildLlmUsageEvidence,
  buildLlmUsageReceiptIntent,
  hashBytes,
  hashProviderPayload,
  maybeStoreExternalPayloads,
  stableStringify,
} from "./evidence.js";
export {
  ReceiptEmissionError,
  emitUsageReceipt,
  receiptPendingFromError,
  resolveReceiptPending,
} from "./receipt.js";
export {
  createReceiptedOpenAIClient,
  createReceiptedOpenAIProxy,
  parseSseStream,
  usageFromChatCompletions,
  usageFromResponses,
} from "./openai.js";
export { createReceiptedMcpProxy } from "./mcp.js";
export type * from "./types.js";
