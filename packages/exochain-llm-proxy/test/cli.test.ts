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
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const cliPath = new URL("../src/cli.js", import.meta.url);

function runCli(command: string, extraEnv: Record<string, string> = {}) {
  return spawnSync(process.execPath, [cliPath.pathname, command], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      ...extraEnv,
    },
  });
}

const configuredEnv = {
  EXOCHAIN_GATEWAY_URL: "https://exochain.example",
  EXOCHAIN_TENANT_ID: "tenant-alpha",
  EXOCHAIN_NAMESPACE: "default",
  EXOCHAIN_ACTOR_DID: "did:exo:agent",
  EXOCHAIN_LYNK_ADAPTER_DID: "did:exo:lynk-adapter",
  EXOCHAIN_LYNK_CUSTODY_POLICY_HASH:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  EXOCHAIN_LYNK_STORAGE_MODE: "receipt_minimized",
  EXOCHAIN_LYNK_IDEMPOTENCY_KEY: "tenant-alpha-run-001",
};

test("CLI rejects unsupported commands for future waves", () => {
  const result = runCli("anthropic", configuredEnv);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /openai\|mcp\|receipt-status/);
});

test("CLI fails closed when required config is missing", () => {
  const result = runCli("openai");

  assert.equal(result.status, 2);
  assert.match(result.stderr, /missing required environment variable EXOCHAIN_GATEWAY_URL/);
});

test("CLI reports configured status without secret-bearing fields", () => {
  const result = runCli("receipt-status", configuredEnv);

  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout) as Record<string, unknown>;
  assert.equal(output.command, "receipt-status");
  assert.equal(output.status, "configured");
  assert.equal(output.storage_mode, "receipt_minimized");
  assert.equal("provider_api_key" in output, false);
  assert.equal("bearer_token" in output, false);
});
