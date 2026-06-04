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

const EXPECTED_BOB_ESCALATION_IDS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-OPTIONAL-ADJACENT',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

test('source council-escalation guard enforces narrowed Bob escalation register coverage', async () => {
  const { scanCouncilEscalationCoverage } = await import('../scripts/source-council-escalation-guard.mjs');
  const report = scanCouncilEscalationCoverage();

  assert.equal(report.schema, 'cybermedica.source_council_escalation_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.deepEqual(report.allowedBobEscalationIds, EXPECTED_BOB_ESCALATION_IDS);
  assert.equal(report.allowedBobEscalationCount, 10);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/ground-truth-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/open-question-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/release-readiness-matrix.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/sandy-review-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/scope-legal-review-register.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/ground-truth-register.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/open-question-register.test.mjs'));
});

