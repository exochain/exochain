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
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';

const EXPECTED_OPEN_QUESTION_IDS = Object.freeze([
  'ADJ-001',
  'ADJ-002',
  'ADJ-003',
  'ADJ-004',
  'ADJ-005',
  'CONSENT-001',
  'CONSENT-002',
  'CONSENT-003',
  'DF-001',
  'DF-002',
  'DF-003',
  'DF-004',
  'DF-005',
  'ID-001',
  'ID-002',
  'ID-003',
  'ID-004',
  'ID-005',
  'PRIV-001',
  'PRIV-002',
  'ROOT-001',
  'ROOT-002',
  'ROOT-003',
  'ROOT-004',
  'ROOT-005',
  'RT-001',
  'RT-002',
  'RT-003',
  'RT-004',
  'RT-005',
]);

const EXPECTED_ESCALATION_IDS = Object.freeze([
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

test('source open-question guard enforces council-default and narrowed escalation coverage', async () => {
  const { scanOpenQuestionCoverage } = await import('../scripts/source-open-question-guard.mjs');
  const report = scanOpenQuestionCoverage();

  assert.equal(report.schema, 'cybermedica.source_open_question_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.deepEqual(report.openQuestionIds, EXPECTED_OPEN_QUESTION_IDS);
  assert.deepEqual(report.narrowedEscalationIds, EXPECTED_ESCALATION_IDS);
  assert.equal(report.openQuestionCount, 30);
  assert.equal(report.narrowedEscalationCount, 10);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/open-question-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/ground-truth-register.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/open-question-register.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/ground-truth-register.test.mjs'));
});

test('source open-question guard emits metadata-only drift findings', async () => {
  const { scanOpenQuestionCoverage } = await import('../scripts/source-open-question-guard.mjs');
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'cybermedica-open-question-guard-'));
  const contextDir = join(fixtureRoot, 'docs', 'context');
  mkdirSync(contextDir, { recursive: true });
  writeFileSync(
    join(contextDir, 'EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md'),
    `# Fixture\n\n| ID | Question | Why it matters | Source basis | Blocked claim |\n|---|---|---|---|---|\n| ROOT-001 | Who are the 13 rostered independent certifiers? | Root requires a roster. | crates/exo-root | root-backed production authority |\n`,
  );
  writeFileSync(
    join(contextDir, 'EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md'),
    `# Fixture\n\nBaseline development must proceed using the consensus defaults below.\n\n| ID | Council-style disposition | Baseline development default | Production claim gate | Escalate to Bob? |\n|---|---|---|---|---:|\n| ROOT-001 | No consensus. | Inactive roster contract. | Verified roster. | Yes |\n\n| Escalation ID | Open question IDs | Required Bob/root/operator input |\n|---|---|---|\n| ESC-ROOT-ROSTER | ROOT-001 | Roster. |\n`,
  );

  const report = scanOpenQuestionCoverage(fixtureRoot);

  assert.equal(report.status, 'failed');
  assert.equal(report.exitCode, 1);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.findingsCount > 0);
  assert.ok(report.findings.every((finding) => finding.metadataOnly === true));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'open_question_id_absent'));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'open_question_source_file_absent'));
});
