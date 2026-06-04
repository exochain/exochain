#!/usr/bin/env node
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

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const COUNCIL_ESCALATION_REGISTER_REF = 'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md';

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

const SOURCE_SCAN_ROOTS = Object.freeze([
  'README.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
  'scripts',
  'src',
]);

const TEST_SCAN_ROOTS = Object.freeze(['tests']);

const REQUIRED_ALL_ESCALATION_SOURCE_REFS = Object.freeze([
  'src/ground-truth-register.mjs',
  'src/open-question-register.mjs',
  'src/release-readiness-matrix.mjs',
  'src/sandy-review-register.mjs',
  'src/scope-legal-review-register.mjs',
]);

const REQUIRED_ALL_ESCALATION_TEST_REFS = Object.freeze([
  'tests/ground-truth-register.test.mjs',
  'tests/open-question-register.test.mjs',
  'tests/release-readiness-matrix.test.mjs',
  'tests/scope-legal-review-register.test.mjs',
]);

const ESCALATION_ID_RE = /\bESC-[A-Z0-9-]+\b/gu;

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readProjectFile(rootDir, pathRef) {
  const absolutePath = resolve(rootDir, pathRef);
  return existsSync(absolutePath) ? readFileSync(absolutePath, 'utf8') : null;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function listFiles(rootDir, pathRef) {
  const absolutePath = resolve(rootDir, pathRef);
  if (!existsSync(absolutePath)) {
    return [];
  }
  if (statSync(absolutePath).isFile()) {
    return [pathRef];
  }
  return readdirSync(absolutePath, { withFileTypes: true })
    .flatMap((entry) => {
      const childRef = join(pathRef, entry.name);
      const childPath = resolve(rootDir, childRef);
      if (entry.isDirectory()) {
        return listFiles(rootDir, childRef);
      }
      return statSync(childPath).isFile() ? [childRef] : [];
    })
    .sort();
}

function escalationIdsFromText(text) {
  return uniqueSorted([...text.matchAll(ESCALATION_ID_RE)].map((match) => match[0]));
}

function scannedFiles(rootDir, roots) {
  return uniqueSorted(roots.flatMap((pathRef) => listFiles(rootDir, pathRef))).filter(
    (pathRef) =>
      pathRef.endsWith('.md') ||
      pathRef.endsWith('.mjs') ||
      pathRef.endsWith('.json') ||
      pathRef.endsWith('.test.mjs'),
  );
}

function sourceFilesWithEscalations(rootDir, roots) {
  return scannedFiles(rootDir, roots).filter((pathRef) => {
    const text = readProjectFile(rootDir, pathRef);
    return text !== null && escalationIdsFromText(text).length > 0;
  });
}

function registerFindings(registerText, allowedIds) {
  if (registerText === null) {
    return [
      {
        ruleId: 'council_escalation_register_file_absent',
        escalationId: null,
        pathRef: COUNCIL_ESCALATION_REGISTER_REF,
        metadataOnly: true,
      },
    ];
  }

  const observedIds = escalationIdsFromText(registerText);
  const observedSet = new Set(observedIds);
  const expectedSet = new Set(EXPECTED_BOB_ESCALATION_IDS);

  return [
    ...EXPECTED_BOB_ESCALATION_IDS.filter((escalationId) => !observedSet.has(escalationId)).map(
      (escalationId) => ({
        ruleId: 'council_escalation_register_id_absent',
        escalationId,
        pathRef: COUNCIL_ESCALATION_REGISTER_REF,
        metadataOnly: true,
      }),
    ),
    ...observedIds.filter((escalationId) => !expectedSet.has(escalationId)).map((escalationId) => ({
      ruleId: 'council_escalation_register_id_unexpected',
      escalationId,
      pathRef: COUNCIL_ESCALATION_REGISTER_REF,
      metadataOnly: true,
    })),
    ...allowedIds.filter((escalationId) => !observedSet.has(escalationId)).map((escalationId) => ({
      ruleId: 'council_escalation_allowed_id_not_in_register',
      escalationId,
      pathRef: COUNCIL_ESCALATION_REGISTER_REF,
      metadataOnly: true,
    })),
  ];
}

function unsupportedSourceFindings(rootDir, checkedSourceRefs, allowedIds) {
  const allowedSet = new Set(allowedIds);
  return checkedSourceRefs.flatMap((pathRef) => {
    const text = readProjectFile(rootDir, pathRef);
    const ids = text === null ? [] : escalationIdsFromText(text);
    return ids
      .filter((escalationId) => !allowedSet.has(escalationId))
      .map((escalationId) => ({
        ruleId: 'source_bob_escalation_id_unsupported',
        escalationId,
        pathRef,
        metadataOnly: true,
      }));
  });
}

function coverageFindings(rootDir, pathRefs, allowedIds, kind) {
  return pathRefs.flatMap((pathRef) => {
    const text = readProjectFile(rootDir, pathRef);
    if (text === null) {
      return [
        {
          ruleId: 'council_escalation_coverage_file_absent',
          escalationId: null,
          pathRef,
          kind,
          metadataOnly: true,
        },
      ];
    }
    const observedSet = new Set(escalationIdsFromText(text));
    return allowedIds
      .filter((escalationId) => !observedSet.has(escalationId))
      .map((escalationId) => ({
        ruleId: 'council_escalation_coverage_id_absent',
        escalationId,
        pathRef,
        kind,
        metadataOnly: true,
      }));
  });
}

function compareFindings(left, right) {
  const pathCompare = String(left.pathRef).localeCompare(String(right.pathRef));
  if (pathCompare !== 0) {
    return pathCompare;
  }
  const escalationCompare = String(left.escalationId).localeCompare(String(right.escalationId));
  if (escalationCompare !== 0) {
    return escalationCompare;
  }
  return left.ruleId.localeCompare(right.ruleId);
}

export function scanCouncilEscalationCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const registerText = readProjectFile(rootDir, COUNCIL_ESCALATION_REGISTER_REF);
  const allowedBobEscalationIds =
    registerText === null ? [...EXPECTED_BOB_ESCALATION_IDS] : escalationIdsFromText(registerText);
  const checkedSourceRefs = sourceFilesWithEscalations(rootDir, SOURCE_SCAN_ROOTS);
  const checkedTestRefs = sourceFilesWithEscalations(rootDir, TEST_SCAN_ROOTS);
  const findings = [
    ...registerFindings(registerText, allowedBobEscalationIds),
    ...unsupportedSourceFindings(rootDir, checkedSourceRefs, allowedBobEscalationIds),
    ...coverageFindings(rootDir, REQUIRED_ALL_ESCALATION_SOURCE_REFS, allowedBobEscalationIds, 'source'),
    ...coverageFindings(rootDir, REQUIRED_ALL_ESCALATION_TEST_REFS, allowedBobEscalationIds, 'test'),
  ].sort(compareFindings);

  return {
    schema: 'cybermedica.source_council_escalation_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-council-escalation-guard',
    scannerVersionHash: sha256Hex(EXPECTED_BOB_ESCALATION_IDS.join('|')),
    councilEscalationRegisterRef: COUNCIL_ESCALATION_REGISTER_REF,
    allowedBobEscalationIds,
    allowedBobEscalationCount: allowedBobEscalationIds.length,
    checkedSourceRefs,
    checkedTestRefs,
    requiredAllEscalationSourceRefs: [...REQUIRED_ALL_ESCALATION_SOURCE_REFS],
    requiredAllEscalationTestRefs: [...REQUIRED_ALL_ESCALATION_TEST_REFS],
    exochainSourceExcluded: [...checkedSourceRefs, ...checkedTestRefs].every(
      (pathRef) => !pathRef.startsWith('../exochain') && !pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
    ),
    findings,
    findingsCount: findings.length,
    metadataOnly: true,
  };
}

const invokedPath = process.argv[1] === undefined ? '' : resolve(process.argv[1]);
const modulePath = fileURLToPath(import.meta.url);

if (invokedPath === modulePath) {
  const rootDir = resolve(dirname(modulePath), '..');
  const report = scanCouncilEscalationCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}

