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
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { scanPathRefs as scanSourceHazards } from '../scripts/source-hazard-scan.mjs';

const root = resolve(import.meta.dirname, '..');
const testedAliases = new Map([
  [
    'trust-adapter.mjs',
    [
      'trust-adapter.test.mjs',
      'adapter-fail-closed.test.mjs',
      'production-trust-activation.test.mjs',
    ],
  ],
]);

function readProjectFile(path) {
  return readFileSync(resolve(root, path), 'utf8');
}

function listFiles(dir) {
  const absolute = resolve(root, dir);
  const entries = readdirSync(absolute, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = join(absolute, entry.name);
    const projectPath = fullPath.slice(root.length + 1);
    if (entry.isDirectory()) {
      return listFiles(projectPath);
    }
    return statSync(fullPath).isFile() ? [projectPath] : [];
  });
}

test('CyberMedica package exposes focused test coverage audit scan and build gates', () => {
  const pkg = JSON.parse(readProjectFile('package.json'));

  assert.equal(pkg.private, true);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.scripts.test, 'node --test tests/*.test.mjs');
  assert.equal(
    pkg.scripts['test:coverage'],
    'node --experimental-test-coverage --test-coverage-lines=90 --test tests/*.test.mjs',
  );
  assert.equal(pkg.scripts['lint:typecheck'], 'node --test tests/source-guards.test.mjs');
  assert.equal(pkg.scripts['audit:deps'], 'npm audit --package-lock-only --audit-level=moderate');
  assert.equal(pkg.scripts['scan:hazards'], 'node scripts/source-hazard-scan.mjs');
  assert.equal(pkg.scripts['scan:secrets'], 'node scripts/source-secret-scan.mjs');
  assert.equal(pkg.scripts['guard:activation-gates'], 'node scripts/source-activation-gate-guard.mjs');
  assert.equal(pkg.scripts['guard:council-escalations'], 'node scripts/source-council-escalation-guard.mjs');
  assert.equal(pkg.scripts['guard:lineage'], 'node scripts/source-lineage-guard.mjs');
  assert.equal(pkg.scripts['guard:adapter-contracts'], 'node scripts/source-adapter-contract-guard.mjs');
  assert.equal(pkg.scripts['guard:adjacent-decisions'], 'node scripts/source-adjacent-surface-decision-guard.mjs');
  assert.equal(pkg.scripts['guard:open-questions'], 'node scripts/source-open-question-guard.mjs');
  assert.equal(pkg.scripts['guard:context-seed'], 'node scripts/source-context-seed-guard.mjs');
  assert.equal(pkg.scripts['guard:glossary'], 'node scripts/source-glossary-guard.mjs');
  assert.equal(pkg.scripts['guard:integration-map'], 'node scripts/source-integration-map-guard.mjs');
  assert.equal(pkg.scripts['build:artifact'], 'npm pack --dry-run --json');
  assert.equal(
    pkg.scripts.quality,
    'npm run lint:typecheck && npm run audit:deps && npm run scan:hazards && npm run scan:secrets && npm run guard:activation-gates && npm run guard:council-escalations && npm run guard:lineage && npm run guard:adapter-contracts && npm run guard:adjacent-decisions && npm run guard:open-questions && npm run guard:context-seed && npm run guard:glossary && npm run guard:integration-map && npm run build:artifact && npm run test && npm run test:coverage',
  );
  assert.deepEqual(pkg.files, [
    'CyberMedica_QMS_PRD_Master.docx',
    'CyberMedica_QMS_PRD_Master.pdf',
    'README.md',
    'cyber_medica_qms_prd_master.md',
    'cybermedica_2_0_sandy_seven_layer_master_prd.md',
    'docs/context',
    'docs/implementation',
    'scripts',
    'src',
    'tests',
  ]);
});

test('source and quality-gate scripts avoid deterministic runtime hazards and placeholder language', () => {
  for (const path of [...listFiles('src'), ...listFiles('scripts')]) {
    const source = readProjectFile(path);
    assert.doesNotMatch(source, /\bDate\.now\b|\bnew Date\b|\bMath\.random\b|\bcrypto\.randomUUID\b/u, path);
    assert.doesNotMatch(source, /\bTODO\b|\bstub\b|\bmock\b|\bfuture phase\b/iu, path);
    assert.doesNotMatch(source, /root-backed production authority/iu, path);
  }
});

test('source hazard scanner backs deterministic source-control evidence', () => {
  const report = scanSourceHazards(root);

  assert.equal(report.schema, 'cybermedica.source_hazard_scan.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.deterministicHazardsAbsent, true);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.scannedFileRefs.includes('scripts/source-hazard-scan.mjs'));
  assert.ok(report.scannedFileRefs.includes('src/ci-cd-quality-gates.mjs'));
  assert.ok(report.scannedFileRefs.includes('tests/source-hazard-scan.test.mjs'));
});

test('source lineage guard backs production-claim-lift runtime-source evidence propagation', async () => {
  const { scanProductionClaimLiftLineage } = await import('../scripts/source-lineage-guard.mjs');
  const report = scanProductionClaimLiftLineage(root);

  assert.equal(report.schema, 'cybermedica.source_lineage_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/release-readiness-matrix.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/trust-adapter.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/production-trust-activation.test.mjs'));
});

test('source adapter-contract guard backs integration-map minimum adapter contract coverage', async () => {
  const { scanMinimumAdapterContractCoverage } = await import('../scripts/source-adapter-contract-guard.mjs');
  const report = scanMinimumAdapterContractCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_adapter_contract_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.minimumAdapterRequirementCount, 5);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/trust-adapter.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/adapter-fail-closed.test.mjs'));
});

test('source adjacent-surface decision guard backs ASD doctrine source and test coverage', async () => {
  const { scanAdjacentSurfaceDecisionCoverage } = await import('../scripts/source-adjacent-surface-decision-guard.mjs');
  const report = scanAdjacentSurfaceDecisionCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_adjacent_surface_decision_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.adjacentSurfaceDecisionCount, 11);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/service-contract-publication.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/service-contract-publication.test.mjs'));
});

test('source open-question guard backs council defaults and narrowed Bob escalations', async () => {
  const { scanOpenQuestionCoverage } = await import('../scripts/source-open-question-guard.mjs');
  const report = scanOpenQuestionCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_open_question_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.openQuestionCount, 30);
  assert.equal(report.narrowedEscalationCount, 10);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/open-question-register.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/open-question-register.test.mjs'));
});

test('source context-seed guard backs controlling doctrine source and test coverage', async () => {
  const { scanContextSeedDoctrineCoverage } = await import('../scripts/source-context-seed-guard.mjs');
  const report = scanContextSeedDoctrineCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_context_seed_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.guardrailCount, 15);
  assert.equal(report.permittedPrimitiveFamilyCount, 11);
  assert.equal(report.forbiddenProductionClaimFamilyCount, 9);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/service-contract-publication.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/service-contract-publication.test.mjs'));
});

test('source glossary guard backs canonical term doctrine source and test coverage', async () => {
  const { scanGlossaryDoctrineCoverage } = await import('../scripts/source-glossary-guard.mjs');
  const report = scanGlossaryDoctrineCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_glossary_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.glossaryTermCount, 50);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/ground-truth-register.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/ground-truth-register.test.mjs'));
});

test('source integration-map guard backs primitive and avoid-list doctrine coverage', async () => {
  const { scanIntegrationMapCoverage } = await import('../scripts/source-integration-map-guard.mjs');
  const report = scanIntegrationMapCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_integration_map_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.integrationNeedCount, 24);
  assert.equal(report.avoidTrustClaimPrimitiveCount, 7);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/tenant-isolation.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/root-trust-registry.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/optional-trust-claim-guards.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/tenant-isolation.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/optional-trust-claim-guards.test.mjs'));
});

test('source activation-gate guard backs every production trust gate with owned source and tests', async () => {
  const { scanActivationGateCoverage } = await import('../scripts/source-activation-gate-guard.mjs');
  const report = scanActivationGateCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_activation_gate_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.productionGateCount, 18);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/exochain-anchoring.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/qms-control-approvals.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/consent-materials.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/exochain-anchoring.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/qms-control-approvals.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/consent-materials.test.mjs'));
});

test('source council-escalation guard backs narrowed Bob escalation register coverage', async () => {
  const { scanCouncilEscalationCoverage } = await import('../scripts/source-council-escalation-guard.mjs');
  const report = scanCouncilEscalationCoverage(root);

  assert.equal(report.schema, 'cybermedica.source_council_escalation_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.equal(report.allowedBobEscalationCount, 10);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/ground-truth-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/open-question-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/release-readiness-matrix.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/ground-truth-register.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/open-question-register.test.mjs'));
});

test('adjacent surface intake has concrete CyberMedica gates', () => {
  const intake = readProjectFile('docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md');

  assert.doesNotMatch(intake, /To be defined when CyberMedica stack is initialized/i);
  assert.match(intake, /npm test/);
  assert.match(intake, /npm run test:coverage/);
  assert.match(intake, /node --test tests\/\*\.test\.mjs/);
});

test('implemented contracts stay documented classified and covered by tests', () => {
  const readme = readProjectFile('README.md');
  const pathClassification = readProjectFile('docs/implementation/PATH_CLASSIFICATION.md');
  const testFiles = new Set(readdirSync(resolve(root, 'tests')).filter((entry) => entry.endsWith('.test.mjs')));

  for (const sourcePath of listFiles('src').filter((path) => path.endsWith('.mjs')).sort()) {
    const sourceFile = sourcePath.slice('src/'.length);
    const sameNameTest = sourceFile.replace(/\.mjs$/u, '.test.mjs');
    const acceptedTests = testedAliases.get(sourceFile) ?? [sameNameTest];

    assert.match(readme, new RegExp(`\\\`src/${sourceFile}\\\``), `${sourcePath} missing README contract row`);
    assert.match(
      pathClassification,
      new RegExp(`/src/${sourceFile}\\\``),
      `${sourcePath} missing path-classification source row`,
    );

    for (const testFile of acceptedTests) {
      assert.ok(testFiles.has(testFile), `${sourcePath} expected test file ${testFile}`);
      assert.match(
        pathClassification,
        new RegExp(`/tests/${testFile}\\\``),
        `${sourcePath} missing path-classification test row for ${testFile}`,
      );
    }
  }
});
