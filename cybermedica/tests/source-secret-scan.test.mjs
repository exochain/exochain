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

import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

async function loadSourceSecretScan() {
  try {
    return await import('../scripts/source-secret-scan.mjs');
  } catch (error) {
    assert.fail(`CyberMedica source secret scanner must exist and load: ${error.message}`);
  }
}

test('source secret scanner detects high-confidence secrets without echoing values', async () => {
  const { scanTextForSecretFindings } = await loadSourceSecretScan();
  const secretValue = ['sk_live_', '1234567890abcdefghijklmnopqrstuv'].join('');

  const findings = scanTextForSecretFindings(
    'src/runtime-config.mjs',
    `const stripeKey = "${secretValue}";`,
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'stripe_live_secret_key');
  assert.equal(findings[0].pathRef, 'src/runtime-config.mjs');
  assert.equal(findings[0].lineNumber, 1);
  assert.equal(findings[0].metadataOnly, true);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(secretValue, 'u'));
});

test('source secret scanner detects each high-confidence rule as metadata-only findings', async () => {
  const { scanTextForSecretFindings } = await loadSourceSecretScan();
  const fixtures = [
    ['aws_access_key_id', ['AKIA', '1234567890ABCDEF'].join('')],
    ['github_token', ['ghp_', 'abcdefghijklmnopqrstuvwx1234567890'].join('')],
    ['google_api_key', ['AIza', '1234567890abcdefghijklmnopqrstuvwxy'].join('')],
    ['jwt_token', ['eyJ', 'a'.repeat(20), '.', 'b'.repeat(20), '.', 'c'.repeat(20)].join('')],
    ['openai_api_key', ['sk-', 'a'.repeat(40)].join('')],
    ['private_key_block', ['-----BEGIN ', 'PRIVATE KEY-----'].join('')],
    ['stripe_live_secret_key', ['sk_live_', '1234567890abcdefghijklmnopqrstuv'].join('')],
  ];

  const source = fixtures.map(([, value], index) => `const value${index} = "${value}";`).join('\n');
  const findings = scanTextForSecretFindings('src/runtime-config.mjs', source);

  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    fixtures.map(([ruleId]) => ruleId),
  );
  assert.deepEqual(
    findings.map((finding) => finding.lineNumber),
    [1, 2, 3, 4, 5, 6, 7],
  );
  assert.equal(findings.every((finding) => finding.metadataOnly === true), true);
  const serializedFindings = JSON.stringify(findings);
  for (const [, value] of fixtures) {
    assert.equal(serializedFindings.includes(value), false);
  }
});

test('source secret scanner treats vault refs and named secret controls as inert metadata', async () => {
  const { scanTextForSecretFindings } = await loadSourceSecretScan();

  const inertFixture = `
    const evidence = {
      apiKey: { vaultRef: 'secret-ref-alpha' },
      scannerRef: 'cybermedica-source-secret-scan',
      commandRef: 'source secret scan',
      secretMaterialAbsent: true
    };
  `;

  assert.deepEqual(scanTextForSecretFindings('tests/ci-cd-quality-gates.test.mjs', inertFixture), []);
});

test('source secret scanner deterministically filters path refs and excludes Exochain source', async () => {
  const { scanPathRefs } = await loadSourceSecretScan();
  const rootDir = join(process.cwd(), '.codex-test-secret-scan');
  rmSync(rootDir, { recursive: true, force: true });
  mkdirSync(join(rootDir, 'src', 'nested'), { recursive: true });
  mkdirSync(join(rootDir, 'src', '.git'), { recursive: true });
  mkdirSync(join(rootDir, 'src', 'node_modules'), { recursive: true });

  try {
    writeFileSync(join(rootDir, 'README.md'), 'clean metadata\n');
    writeFileSync(join(rootDir, 'notes.txt'), ['sk-', 'a'.repeat(40)].join(''));
    writeFileSync(join(rootDir, 'src', 'alpha.mjs'), 'export const ok = true;\n');
    writeFileSync(join(rootDir, 'src', 'nested', 'beta.json'), '{"ok":true}\n');
    writeFileSync(join(rootDir, 'src', '.git', 'ignored.mjs'), ['sk-', 'b'.repeat(40)].join(''));
    writeFileSync(join(rootDir, 'src', 'node_modules', 'ignored.mjs'), ['sk-', 'c'.repeat(40)].join(''));

    const report = scanPathRefs(rootDir, [
      'src',
      'src',
      'missing',
      'notes.txt',
      '../exochain',
      '/Users/bobstewart/dev/exochain/exochain',
      'README.md',
    ]);

    assert.equal(report.status, 'passed');
    assert.equal(report.findingsCount, 0);
    assert.equal(report.metadataOnly, true);
    assert.equal(report.exochainSourceExcluded, false);
    assert.deepEqual(report.scannedPathRefs, [
      '../exochain',
      '/Users/bobstewart/dev/exochain/exochain',
      'README.md',
      'missing',
      'notes.txt',
      'src',
    ]);
    assert.deepEqual(report.scannedFileRefs, ['README.md', 'src/alpha.mjs', 'src/nested/beta.json']);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('source secret scanner reports current package scopes as clean metadata-only evidence', async () => {
  const { scanPathRefs } = await loadSourceSecretScan();

  const report = scanPathRefs(process.cwd());

  assert.equal(report.schema, 'cybermedica.source_secret_scan.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.highRiskFindingsCount, 0);
  assert.equal(report.metadataOnly, true);
  assert.equal(report.exochainSourceExcluded, true);
  assert.deepEqual(report.scannedPathRefs, [
    'README.md',
    'docs/context',
    'docs/implementation',
    'package-lock.json',
    'package.json',
    'scripts',
    'src',
    'tests',
  ]);
});
