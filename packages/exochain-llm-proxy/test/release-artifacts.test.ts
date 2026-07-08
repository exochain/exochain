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
import { existsSync, readFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { test } from "node:test";

test("release artifacts are present and agent discoverable", async () => {
  for (const path of [
    "README.md",
    "AGENTS.md",
    "snippets/env-template.md",
    "snippets/agent-integration-brief.md",
    "snippets/receipt-pending-runbook.md",
  ]) {
    assert.equal(existsSync(path), true, `${path} must exist`);
  }
  const examples = (await readdir("examples")).filter((name) => name.endsWith(".ts"));
  assert.equal(examples.length >= 5, true);
  const readme = readFileSync("README.md", "utf8");
  assert.match(readme, /EXOCHAIN LYNK Protocol/);
  assert.match(readme, /receipt_pending/);
});

test("release artifacts do not contain secret-shaped example values", async () => {
  const paths = [
    "README.md",
    "AGENTS.md",
    "snippets/env-template.md",
    "snippets/agent-integration-brief.md",
    "snippets/receipt-pending-runbook.md",
    ...(await readdir("examples")).map((name) => `examples/${name}`),
  ];
  for (const path of paths) {
    const text = readFileSync(path, "utf8");
    assert.equal(text.includes("sk-live"), false, `${path} must not contain live key prefixes`);
    assert.equal(text.includes("s3://"), false, `${path} must not contain raw object locations`);
    const bannedCustodyOverclaim = ["never stores", "decryptable payload material"].join(" ");
    assert.equal(text.includes(bannedCustodyOverclaim), false);
  }
});
