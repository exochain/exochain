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

const BASE_RUNTIME_SOURCE_FIELDS = Object.freeze([
  'productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash',
  'productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash',
  'productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash',
  'productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash',
  'productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash',
  'productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash',
]);

const ADAPTER_ACTIVATION_RUNTIME_SOURCE_FIELDS = Object.freeze([
  'productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash',
  'productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash',
  'productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash',
  'productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash',
  'productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash',
  'productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash',
]);

function prefixedFields(prefix, fields) {
  return fields.map((field) => `${prefix}${field[0].toUpperCase()}${field.slice(1)}`);
}

const PUBLIC_CLAIM_REVIEW_RUNTIME_SOURCE_FIELDS = Object.freeze(
  prefixedFields('publicClaimReview', BASE_RUNTIME_SOURCE_FIELDS),
);

const PUBLIC_CLAIM_REVIEW_ADAPTER_ACTIVATION_FIELDS = Object.freeze(
  prefixedFields('publicClaimReview', ADAPTER_ACTIVATION_RUNTIME_SOURCE_FIELDS),
);

const REQUIRED_SOURCE_CONTRACTS = Object.freeze([
  'src/release-readiness-matrix.mjs',
  'src/deployment-readiness-manifest.mjs',
  'src/deployment-operations-readiness.mjs',
  'src/deployment-provider-binding.mjs',
  'src/deployment-handoff-cutover.mjs',
  'src/runtime-configuration-source.mjs',
  'src/adapter-activation-evidence.mjs',
  'src/production-claim-lifting.mjs',
  'src/public-claim-review.mjs',
].map((pathRef) => ({
  pathRef,
  requiredTextRefs: BASE_RUNTIME_SOURCE_FIELDS,
})));

const REQUIRED_ACTIVATION_SOURCE_CONTRACTS = Object.freeze([
  {
    pathRef: 'src/trust-adapter.mjs',
    requiredTextRefs: [
      ...BASE_RUNTIME_SOURCE_FIELDS,
      ...ADAPTER_ACTIVATION_RUNTIME_SOURCE_FIELDS,
      ...PUBLIC_CLAIM_REVIEW_RUNTIME_SOURCE_FIELDS,
      ...PUBLIC_CLAIM_REVIEW_ADAPTER_ACTIVATION_FIELDS,
    ],
  },
  {
    pathRef: 'src/trust-state-view.mjs',
    requiredTextRefs: [
      ...PUBLIC_CLAIM_REVIEW_RUNTIME_SOURCE_FIELDS,
      ...PUBLIC_CLAIM_REVIEW_ADAPTER_ACTIVATION_FIELDS,
    ],
  },
  {
    pathRef: 'src/role-dashboards.mjs',
    requiredTextRefs: [
      ...PUBLIC_CLAIM_REVIEW_RUNTIME_SOURCE_FIELDS,
      ...PUBLIC_CLAIM_REVIEW_ADAPTER_ACTIVATION_FIELDS,
    ],
  },
]);

const REQUIRED_TEST_CONTRACTS = Object.freeze([
  'tests/release-readiness-matrix.test.mjs',
  'tests/deployment-readiness-manifest.test.mjs',
  'tests/deployment-operations-readiness.test.mjs',
  'tests/deployment-provider-binding.test.mjs',
  'tests/deployment-handoff-cutover.test.mjs',
  'tests/runtime-configuration-source.test.mjs',
  'tests/adapter-activation-evidence.test.mjs',
  'tests/production-claim-lifting.test.mjs',
  'tests/public-claim-review.test.mjs',
  'tests/trust-adapter.test.mjs',
  'tests/trust-state-view.test.mjs',
  'tests/production-trust-activation.test.mjs',
].map((pathRef) => ({
  pathRef,
  requiredTextRefs: BASE_RUNTIME_SOURCE_FIELDS,
})));

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readProjectFile(rootDir, pathRef) {
  const absolutePath = resolve(rootDir, pathRef);
  return existsSync(absolutePath) ? readFileSync(absolutePath, 'utf8') : null;
}

function evaluateContract(rootDir, contract, kind) {
  const source = readProjectFile(rootDir, contract.pathRef);
  if (source === null) {
    return [
      {
        ruleId: 'lineage_file_absent',
        kind,
        pathRef: contract.pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return contract.requiredTextRefs
    .filter((requiredTextRef) => !source.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId: 'lineage_text_absent',
      kind,
      pathRef: contract.pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

export function scanProductionClaimLiftLineage(rootDir = process.cwd()) {
  const sourceContracts = [...REQUIRED_SOURCE_CONTRACTS, ...REQUIRED_ACTIVATION_SOURCE_CONTRACTS];
  const testContracts = [...REQUIRED_TEST_CONTRACTS];
  const findings = [
    ...sourceContracts.flatMap((contract) => evaluateContract(rootDir, contract, 'source')),
    ...testContracts.flatMap((contract) => evaluateContract(rootDir, contract, 'test')),
  ].sort((left, right) => {
    const pathCompare = left.pathRef.localeCompare(right.pathRef);
    if (pathCompare !== 0) {
      return pathCompare;
    }
    return String(left.requiredTextRef).localeCompare(String(right.requiredTextRef));
  });

  const lineageFieldRefs = uniqueSorted([
    ...BASE_RUNTIME_SOURCE_FIELDS,
    ...ADAPTER_ACTIVATION_RUNTIME_SOURCE_FIELDS,
    ...PUBLIC_CLAIM_REVIEW_RUNTIME_SOURCE_FIELDS,
    ...PUBLIC_CLAIM_REVIEW_ADAPTER_ACTIVATION_FIELDS,
  ]);

  return {
    schema: 'cybermedica.source_lineage_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-lineage-guard',
    scannerVersionHash: sha256Hex(lineageFieldRefs.join('|')),
    checkedSourceRefs: sourceContracts.map((contract) => contract.pathRef).sort(),
    checkedTestRefs: testContracts.map((contract) => contract.pathRef).sort(),
    lineageFieldRefs,
    exochainSourceExcluded: true,
    findings,
    findingsCount: findings.length,
    metadataOnly: true,
  };
}

const invokedPath = process.argv[1] === undefined ? '' : resolve(process.argv[1]);
const modulePath = fileURLToPath(import.meta.url);

if (invokedPath === modulePath) {
  const rootDir = resolve(dirname(modulePath), '..');
  const report = scanProductionClaimLiftLineage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
