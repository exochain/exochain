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
import { test } from 'node:test';

async function loadSourceHazardScan() {
  try {
    return await import('../scripts/source-hazard-scan.mjs');
  } catch (error) {
    assert.fail(`CyberMedica source hazard scanner must exist and load: ${error.message}`);
  }
}

test('source hazard scanner detects deterministic hazards without echoing source values', async () => {
  const { scanTextForSourceHazards } = await loadSourceHazardScan();
  const hazardSource = [
    'const sampled = Date.now();',
    'const entropy = Math.random();',
    'const ratio = 1.5;',
    'const runner = eval;',
    'while (true) { break; }',
    'for (;;) { break; }',
  ].join('\n');

  const findings = scanTextForSourceHazards('src/hazard-fixture.mjs', hazardSource);

  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    [
      'system_time_source',
      'randomness_source',
      'floating_point_literal',
      'dynamic_code_execution',
      'unbounded_while_loop',
      'unbounded_for_loop',
    ],
  );
  assert.deepEqual(
    findings.map((finding) => finding.lineNumber),
    [1, 2, 3, 4, 5, 6],
  );
  assert.ok(findings.every((finding) => finding.metadataOnly === true));
  assert.ok(findings.every((finding) => /^[0-9a-f]{64}$/u.test(finding.matchDigest)));
  assert.doesNotMatch(JSON.stringify(findings), /Date\.now|Math\.random|1\.5|while \(true\)|for \(;;\)|const runner/u);
});

test('source hazard scanner ignores comments strings regexes and integer fixed-point code', async () => {
  const { scanTextForSourceHazards } = await loadSourceHazardScan();
  const safeSource = [
    '// Apache License Version 2.0 and operator examples are not executable hazards.',
    "const label = 'Date.now Math.random 1.5 while (true) for (;;) eval';",
    'const pattern = /\\d+\\.\\d+/u;',
    'const basisPoints = Number((BigInt(numerator) * 10_000n) / BigInt(denominator));',
    'for (const item of items) { material.push(item); }',
  ].join('\n');

  assert.deepEqual(scanTextForSourceHazards('src/safe-fixture.mjs', safeSource), []);
});

test('source hazard scanner reports current CyberMedica code-bearing sources as clean', async () => {
  const { scanPathRefs } = await loadSourceHazardScan();

  const report = scanPathRefs(process.cwd());

  assert.equal(report.schema, 'cybermedica.source_hazard_scan.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.metadataOnly, true);
  assert.equal(report.exochainSourceExcluded, true);
  assert.deepEqual(report.scannedPathRefs, [
    'README.md',
    'docs/context',
    'docs/implementation',
    'package.json',
    'scripts',
    'src',
    'tests',
  ]);
  assert.ok(report.scannedFileRefs.includes('scripts/source-hazard-scan.mjs'));
  assert.ok(report.scannedFileRefs.includes('src/qms-contracts.mjs'));
  assert.ok(report.scannedFileRefs.includes('tests/source-hazard-scan.test.mjs'));
  assert.ok(!report.scannedFileRefs.some((pathRef) => pathRef.startsWith('../exochain')));
});
