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
  ok(report.checks.some(check => check.name === 'tnc_enforce_all' && check.status === 'pass'));
  ok(report.checks.some(check => check.name === 'invariant_enforcement' && check.status === 'pass'));
});

test('exoforge-monitor --once reports healthy against the live WASM validation contract', async () => {
  const report = await runJsonCli('exoforge/bin/exoforge-monitor.js', ['--once', '--json']);

  equal(report.status, 'healthy');
  equal(report.checks_critical, 0);
  ok(report.checks.some(check => check.check === 'tnc_enforcement' && check.status === 'healthy'));
  ok(report.checks.some(check => check.check === 'invariant_enforcement' && check.status === 'healthy'));
});
