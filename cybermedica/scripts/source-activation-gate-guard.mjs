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
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ACTIVATION_GATE_REGISTER_REF = 'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md';

const EXPECTED_PRODUCTION_GATE_IDS = Object.freeze(
  Array.from({ length: 18 }, (_, index) => `PTAG-${String(index + 1).padStart(3, '0')}`),
);

const REQUIRED_ACTIVATION_GATE_CONTRACTS = Object.freeze([
  {
    gateId: 'PTAG-001',
    sourceRefs: ['src/root-trust-registry.mjs'],
    testRefs: ['tests/root-trust-registry.test.mjs'],
  },
  {
    gateId: 'PTAG-002',
    sourceRefs: ['src/requirement-traceability.mjs'],
    testRefs: ['tests/requirement-traceability.test.mjs'],
  },
  {
    gateId: 'PTAG-003',
    sourceRefs: ['src/exochain-anchoring.mjs'],
    testRefs: ['tests/exochain-anchoring.test.mjs'],
  },
  {
    gateId: 'PTAG-004',
    sourceRefs: ['src/qms-control-approvals.mjs'],
    testRefs: ['tests/qms-control-approvals.test.mjs'],
  },
  {
    gateId: 'PTAG-005',
    sourceRefs: ['src/adapter-activation-evidence.mjs'],
    testRefs: ['tests/adapter-activation-evidence.test.mjs'],
  },
  {
    gateId: 'PTAG-006',
    sourceRefs: ['src/adapter-activation-evidence.mjs'],
    testRefs: ['tests/adapter-activation-evidence.test.mjs'],
  },
  {
    gateId: 'PTAG-007',
    sourceRefs: ['src/consent-materials.mjs'],
    testRefs: ['tests/consent-materials.test.mjs'],
  },
  {
    gateId: 'PTAG-008',
    sourceRefs: ['src/deployment-readiness-manifest.mjs'],
    testRefs: ['tests/deployment-readiness-manifest.test.mjs'],
  },
  {
    gateId: 'PTAG-009',
    sourceRefs: ['src/privacy-fixture-boundary.mjs'],
    testRefs: ['tests/privacy-fixture-boundary.test.mjs'],
  },
  {
    gateId: 'PTAG-010',
    sourceRefs: ['src/clinical-authority-policy.mjs'],
    testRefs: ['tests/clinical-authority-policy.test.mjs'],
  },
  {
    gateId: 'PTAG-011',
    sourceRefs: ['src/syntaxis-workflow-validation.mjs'],
    testRefs: ['tests/syntaxis-workflow-validation.test.mjs'],
  },
  {
    gateId: 'PTAG-012',
    sourceRefs: ['src/optional-trust-claim-guards.mjs'],
    testRefs: ['tests/optional-trust-claim-guards.test.mjs'],
  },
  {
    gateId: 'PTAG-013',
    sourceRefs: ['src/optional-trust-claim-guards.mjs'],
    testRefs: ['tests/optional-trust-claim-guards.test.mjs'],
  },
  {
    gateId: 'PTAG-014',
    sourceRefs: ['src/optional-trust-claim-guards.mjs'],
    testRefs: ['tests/optional-trust-claim-guards.test.mjs'],
  },
  {
    gateId: 'PTAG-015',
    sourceRefs: ['src/optional-trust-claim-guards.mjs'],
    testRefs: ['tests/optional-trust-claim-guards.test.mjs'],
  },
  {
    gateId: 'PTAG-016',
    sourceRefs: ['src/gateway-call-path.mjs'],
    testRefs: ['tests/gateway-call-path.test.mjs'],
  },
  {
    gateId: 'PTAG-017',
    sourceRefs: ['src/node-receipt-sync.mjs'],
    testRefs: ['tests/node-receipt-sync.test.mjs'],
  },
  {
    gateId: 'PTAG-018',
    sourceRefs: ['src/browser-trust-path.mjs'],
    testRefs: ['tests/browser-trust-path.test.mjs'],
  },
]);

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

function productionGateIdsFromRegister(registerText) {
  return uniqueSorted([...registerText.matchAll(/\bPTAG-\d{3}\b/gu)].map((match) => match[0]));
}

function contractForGate(gateId) {
  return REQUIRED_ACTIVATION_GATE_CONTRACTS.find((contract) => contract.gateId === gateId);
}

function fileTextFindings(rootDir, gateId, pathRefs, kind) {
  return pathRefs.flatMap((pathRef) => {
    const text = readProjectFile(rootDir, pathRef);
    if (text === null) {
      return [
        {
          ruleId: `activation_gate_${kind}_file_absent`,
          gateId,
          pathRef,
          metadataOnly: true,
        },
      ];
    }
    if (!text.includes(gateId)) {
      return [
        {
          ruleId: `activation_gate_${kind}_text_absent`,
          gateId,
          pathRef,
          metadataOnly: true,
        },
      ];
    }
    return [];
  });
}

function compareFindings(left, right) {
  const gateCompare = left.gateId.localeCompare(right.gateId);
  if (gateCompare !== 0) {
    return gateCompare;
  }
  const pathCompare = String(left.pathRef).localeCompare(String(right.pathRef));
  if (pathCompare !== 0) {
    return pathCompare;
  }
  return left.ruleId.localeCompare(right.ruleId);
}

export function scanActivationGateCoverage(rootDir = process.cwd()) {
  const registerText = readProjectFile(rootDir, ACTIVATION_GATE_REGISTER_REF);
  const productionGateIds = registerText === null ? [] : productionGateIdsFromRegister(registerText);
  const expectedGateIdSet = new Set(EXPECTED_PRODUCTION_GATE_IDS);
  const observedGateIdSet = new Set(productionGateIds);
  const checkedSourceRefs = uniqueSorted(
    REQUIRED_ACTIVATION_GATE_CONTRACTS.flatMap((contract) => contract.sourceRefs),
  );
  const checkedTestRefs = uniqueSorted(
    REQUIRED_ACTIVATION_GATE_CONTRACTS.flatMap((contract) => contract.testRefs),
  );

  const registerFindings =
    registerText === null
      ? [
          {
            ruleId: 'activation_gate_register_file_absent',
            gateId: null,
            pathRef: ACTIVATION_GATE_REGISTER_REF,
            metadataOnly: true,
          },
        ]
      : [
          ...EXPECTED_PRODUCTION_GATE_IDS.filter((gateId) => !observedGateIdSet.has(gateId)).map((gateId) => ({
            ruleId: 'activation_gate_register_id_absent',
            gateId,
            pathRef: ACTIVATION_GATE_REGISTER_REF,
            metadataOnly: true,
          })),
          ...productionGateIds.filter((gateId) => !expectedGateIdSet.has(gateId)).map((gateId) => ({
            ruleId: 'activation_gate_register_id_unexpected',
            gateId,
            pathRef: ACTIVATION_GATE_REGISTER_REF,
            metadataOnly: true,
          })),
        ];

  const contractFindings = EXPECTED_PRODUCTION_GATE_IDS.flatMap((gateId) => {
    const contract = contractForGate(gateId);
    if (contract === undefined) {
      return [
        {
          ruleId: 'activation_gate_contract_mapping_absent',
          gateId,
          pathRef: null,
          metadataOnly: true,
        },
      ];
    }
    return [
      ...fileTextFindings(rootDir, gateId, contract.sourceRefs, 'source'),
      ...fileTextFindings(rootDir, gateId, contract.testRefs, 'test'),
    ];
  });

  const findings = [...registerFindings, ...contractFindings].sort(compareFindings);

  return {
    schema: 'cybermedica.source_activation_gate_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-activation-gate-guard',
    scannerVersionHash: sha256Hex(
      REQUIRED_ACTIVATION_GATE_CONTRACTS.map(
        (contract) => `${contract.gateId}:${contract.sourceRefs.join(',')}:${contract.testRefs.join(',')}`,
      ).join('|'),
    ),
    activationGateRegisterRef: ACTIVATION_GATE_REGISTER_REF,
    productionGateIds,
    productionGateCount: productionGateIds.length,
    checkedSourceRefs,
    checkedTestRefs,
    exochainSourceExcluded: ![...checkedSourceRefs, ...checkedTestRefs].some(
      (pathRef) => pathRef.startsWith('../exochain') || pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
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
  const report = scanActivationGateCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
