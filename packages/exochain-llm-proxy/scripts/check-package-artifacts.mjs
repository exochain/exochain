#!/usr/bin/env node
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

import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";

const requiredFiles = [
  "README.md",
  "AGENTS.md",
  "dist/index.js",
  "dist/index.d.ts",
  "snippets/env-template.md",
  "snippets/agent-integration-brief.md",
  "snippets/receipt-pending-runbook.md",
];

const requiredExampleCount = 5;

for (const path of requiredFiles) {
  if (!existsSync(path)) {
    console.error(`missing package artifact: ${path}`);
    process.exit(1);
  }
}

const examples = (await readdir("examples")).filter((name) => name.endsWith(".ts"));
if (examples.length < requiredExampleCount) {
  console.error(`expected at least ${requiredExampleCount} TypeScript examples`);
  process.exit(1);
}

console.log("package artifact check passed");
