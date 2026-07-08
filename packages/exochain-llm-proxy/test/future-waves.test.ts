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
import * as publicApi from "../src/index.js";

test("future provider waves are not exported as supported V1 adapters", () => {
  for (const unsupported of [
    "createReceiptedAnthropicClient",
    "createReceiptedGenericApiClient",
    "createReceiptedSdkWrapper",
    "createReceiptedWorkflowProducer",
  ]) {
    assert.equal(
      Object.prototype.hasOwnProperty.call(publicApi, unsupported),
      false,
      `${unsupported} must remain unsupported until its wave lands`,
    );
  }
});

test("V1 public surface stays limited to OpenAI and MCP support lanes", () => {
  assert.equal(typeof publicApi.createReceiptedOpenAIClient, "function");
  assert.equal(typeof publicApi.createReceiptedOpenAIProxy, "function");
  assert.equal(typeof publicApi.createReceiptedMcpProxy, "function");
});
