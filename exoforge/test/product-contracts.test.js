// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import { execFile } from 'node:child_process';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { equal, ok } from 'node:assert/strict';

const execFileAsync = promisify(execFile);

async function runJsonCli(script, args = []) {
  try {
    const { stdout } = await execFileAsync(process.execPath, [script, ...args], {
      cwd: new URL('../..', import.meta.url),
      maxBuffer: 1024 * 1024,
    });
    return JSON.parse(stdout);
  } catch (err) {
    if (err.stdout) return JSON.parse(err.stdout);
    throw err;
  }
}

test('exoforge-implement identifies itself as a planning-only contract', async () => {
  const plan = await runJsonCli('exoforge/bin/exoforge-implement.js', [
    '1',
    '--dry-run',
    '--json',
  ]);

  equal(plan.execution_mode, 'planning_only');
  equal(plan.binding_review, false);
  ok(!JSON.stringify(plan).includes('Actual code implementation requires'));
  ok(!JSON.stringify(plan).includes('requires invoking Claude Code'));
});

test('exoforge-council-review labels heuristic output as non-binding triage', async () => {
  const review = await runJsonCli('exoforge/bin/exoforge-council-review.js', [
    '--json',
    '--title',
    'Constitutional change',
    '--description',
    'Modify authority chain',
  ]);

  equal(review.review_method, 'heuristic_triage');
  equal(review.binding_review, false);
  equal(review.verdict.review_method, 'heuristic_triage');
  equal(review.verdict.binding_review, false);
});
