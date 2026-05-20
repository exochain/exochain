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
  const { stdout } = await execFileAsync(process.execPath, [script, ...args], {
    cwd: new URL('../..', import.meta.url),
    maxBuffer: 1024 * 1024,
  });
  return JSON.parse(stdout);
}

test('exoforge-validate passes against the live WASM validation contract', async () => {
  const report = await runJsonCli('exoforge/bin/exoforge-validate.js', ['--json']);

  equal(report.kernel_loaded, true);
  equal(report.summary.failed, 0);
  ok(report.checks.some(check =>
    check.name === 'tnc_enforce_all' &&
    check.status === 'pass' &&
    check.details.includes('rejected caller-supplied proof flags')
  ));
  ok(report.checks.some(check =>
    check.name === 'invariant_enforcement' &&
    check.status === 'pass' &&
    check.details.includes('rejected caller-supplied trust roots')
  ));
});

test('exoforge-monitor --once reports healthy against the live WASM validation contract', async () => {
  const report = await runJsonCli('exoforge/bin/exoforge-monitor.js', ['--once', '--json']);

  equal(report.status, 'healthy');
  equal(report.checks_critical, 0);
  ok(report.checks.some(check =>
    check.check === 'tnc_enforcement' &&
    check.status === 'healthy' &&
    check.details.includes('rejected caller-supplied proof flags')
  ));
  ok(report.checks.some(check =>
    check.check === 'invariant_enforcement' &&
    check.status === 'healthy' &&
    check.details.includes('rejected caller-supplied trust roots')
  ));
});
