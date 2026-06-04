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

const EXPECTED_GLOSSARY_TERMS = Object.freeze([
  '0dentity',
  '13-certifier DKG',
  '7-of-13 signing',
  'AVC',
  'Adjacent surface',
  'Authority chain',
  'AuthorityChainValid',
  'BCTS',
  'Bailment',
  'Baseline development',
  'Canonical CBOR',
  'Chain of custody',
  'Challenge',
  'CommandBase',
  'Commit certificate',
  'Consent gate',
  'Consent policy',
  'ConsentRequired',
  'Constitutional invariant',
  'Core runtime adapter',
  'CrossChecked anchor',
  'DAG node',
  'DID',
  'DID auth',
  'DecisionObject',
  'Determinism',
  'ExoForge/Archon',
  'Exochain core',
  'Gatekeeper',
  'Governance audit entry',
  'HLC',
  'Human gate',
  'HumanOverride',
  'KernelImmutability',
  'Legal evidence',
  'No floating point',
  'NoSelfGrant',
  'Permission',
  'Production activation',
  'ProvenanceVerifiable',
  'Quorum',
  'QuorumLegitimate',
  'Root genesis',
  'SeparationOfPowers',
  'Syntaxis',
  'TNC',
  'Trust claim by proximity',
  'TrustReceipt',
  'WorkflowReceipt',
  '`exo-proofs`',
]);

test('source glossary guard enforces canonical terms and mapped implementation coverage', async () => {
  const { scanGlossaryDoctrineCoverage } = await import('../scripts/source-glossary-guard.mjs');
  const report = scanGlossaryDoctrineCoverage();

  assert.equal(report.schema, 'cybermedica.source_glossary_guard.v1');
  assert.equal(report.status, 'passed');
  assert.equal(report.exitCode, 0);
  assert.deepEqual(report.glossaryTerms, EXPECTED_GLOSSARY_TERMS);
  assert.equal(report.glossaryTermCount, 50);
  assert.equal(report.findingsCount, 0);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.checkedSourceRefs.includes('src/ground-truth-register.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/trust-adapter.mjs'));
  assert.ok(report.checkedSourceRefs.includes('src/service-contract-publication.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/ground-truth-register.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/adapter-fail-closed.test.mjs'));
  assert.ok(report.checkedTestRefs.includes('tests/service-contract-publication.test.mjs'));
});

test('source glossary guard emits metadata-only drift findings', async () => {
  const { scanGlossaryDoctrineCoverage } = await import('../scripts/source-glossary-guard.mjs');
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'cybermedica-glossary-guard-'));
  const contextDir = join(fixtureRoot, 'docs', 'context');
  mkdirSync(contextDir, { recursive: true });
  writeFileSync(
    join(contextDir, 'EXOCHAIN_GLOSSARY_FOR_CYBERMEDICA.md'),
    `# Fixture

Terms are not available for CyberMedica trust claims unless their implementation path and test requirement are also satisfied.

| Term | Canonical meaning for CyberMedica | Source path | Evidence type | Implementation status | Test/doc status | Confidence | CyberMedica use rule |
|---|---|---|---:|---|---|---:|---|
| Exochain core | Rust trust fabric. | \`crates/*\` | Code | Implemented | Rerun required | High | CyberMedica is not core. |
`,
  );

  const report = scanGlossaryDoctrineCoverage(fixtureRoot);

  assert.equal(report.status, 'failed');
  assert.equal(report.exitCode, 1);
  assert.equal(report.exochainSourceExcluded, true);
  assert.equal(report.metadataOnly, true);
  assert.ok(report.findingsCount > 0);
  assert.ok(report.findings.every((finding) => finding.metadataOnly === true));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'glossary_term_absent'));
  assert.ok(report.findings.some((finding) => finding.ruleId === 'glossary_source_file_absent'));
});
