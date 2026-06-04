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
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const EXPECTED_INTEGRATION_NEEDS = Object.freeze([
  'Tenant isolation',
  'Clinical research site identity',
  'User identity',
  'Role authority',
  'Delegation logs',
  'Participant consent',
  'Support access grants',
  'Evidence object hashing',
  'Chain of custody',
  'Document version receipts',
  'QMS control approval',
  'Protocol launch gate',
  'Enrollment gate',
  'CAPA closure',
  'Sponsor/CRO export',
  'Audit event receipts',
  'AI review provenance',
  'Deterministic scoring',
  'Privacy-preserving anchors',
  'Root-backed production authority',
  'Gateway call path',
  'Node receipt path',
  'Runtime readiness and health',
  'WASM/browser path',
]);

const EXPECTED_AVOID_PRIMITIVES = Object.freeze([
  'ZK proofs',
  'CrossChecked anchoring',
  'Raw admin governance',
  '0dentity device/behavior axes',
  'Economy settlement',
  'CommandBase enforcement',
  'ExoForge/Archon as authority',
]);

test('source integration-map guard enforces primitive map and avoid-list coverage', async () => {
  const { scanIntegrationMapCoverage } = await import('../scripts/source-integration-map-guard.mjs');
  const report = scanIntegrationMapCoverage();

  assert.equal(report.schema, 'cybermedica.source_integration_map_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.deepEqual(report.integrationNeedNames, EXPECTED_INTEGRATION_NEEDS);
  assert.deepEqual(report.avoidTrustClaimPrimitiveNames, EXPECTED_AVOID_PRIMITIVES);
  assert.equal(report.integrationNeedCount, 24);
  assert.equal(report.avoidTrustClaimPrimitiveCount, 7);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/tenant-isolation.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/did-authentication.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/verified-human-provider.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/clinical-authority-policy.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/delegation-audit-log.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/consent-materials.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/support-access.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/qms-contracts.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/evidence-custody.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/document-versions.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/qms-control-approvals.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/decision-forum-matters.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/capa-workflows.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/diligence-exports.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/audit-event-receipts.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/ai-control-review.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/evidence-scoring.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/privacy-fixture-boundary.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/root-trust-registry.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/gateway-call-path.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/node-receipt-sync.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/runtime-readiness.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/browser-trust-path.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/exochain-anchoring.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/optional-trust-claim-guards.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/tenant-isolation.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/did-authentication.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/verified-human-provider.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/optional-trust-claim-guards.test.mjs'));
});

test('source integration-map guard emits metadata-only drift findings', async () => {
  const { scanIntegrationMapCoverage } = await import('../scripts/source-integration-map-guard.mjs');
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'cybermedica-integration-map-'));
  const contextDir = join(fixtureRoot, 'docs', 'context');
  mkdirSync(contextDir, { recursive: true });
  writeFileSync(
    join(contextDir, 'EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md'),
    `# Fixture\n\n## CyberMedica Need Mapping\n\n| CyberMedica Need | Exochain Primitive | Source Path | Adapter Needed? | MVP | Risk | Required Tests | Allowed Claim After Tests |\n|---|---|---|---|---|---|---|---|\n| Tenant isolation | Tenant registry | source | Yes | Yes | risk | tests | tenant-aware access control |\n\n## Primitives CyberMedica Must Avoid for Trust Claims Until Verified\n\n| Primitive or Surface | Source path | Reason |\n|---|---|---|\n| ZK proofs | source | reason |\n`,
  );

  const report = scanIntegrationMapCoverage(fixtureRoot);

  assert.equal(report.status, 'failed');
  assert.equal(report.exitCode, 1);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.findingsCount > 0);
  assert.ok(report.findings.every((finding) => finding.metadataOnly === true));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'integration_map_need_row_absent'));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'integration_map_avoid_row_absent'));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'integration_map_source_file_absent'));
});
