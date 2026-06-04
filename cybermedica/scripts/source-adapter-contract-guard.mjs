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

const INTEGRATION_MAP_REF = 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md';

const EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS = Object.freeze([
  {
    id: 'MAC-001',
    contextText:
      'It fails closed when Exochain is unavailable, returns an error, times out, rejects auth, rejects consent, rejects authority, rejects quorum, or cannot create a receipt.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_service_unavailable',
          'receipt_timeout',
          'gateway_service_unavailable',
          'gateway_timeout',
          'decision_forum_service_unavailable',
          'decision_forum_timeout',
        ]),
      },
      {
        pathRef: 'src/gateway-call-path.mjs',
        requiredTextRefs: Object.freeze([
          'did_authentication_unverified',
          'consent_middleware_unverified',
          'authority_middleware_unverified',
          'quorum_middleware_unverified',
          'gateway_route_unavailable_fail_closed_absent',
          'gateway_route_timeout_fail_closed_absent',
        ]),
      },
      {
        pathRef: 'src/node-receipt-sync.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_signature_missing',
          'query_receipt_id_missing',
          'insert_receipt_id_absent',
          'load_receipt_id_mismatch',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-fail-closed.test.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_service_unavailable',
          'receipt_timeout',
          'gateway_service_unavailable',
          'gateway_timeout',
          'decision_forum_service_unavailable',
          'decision_forum_timeout',
        ]),
      },
      {
        pathRef: 'tests/gateway-call-path.test.mjs',
        requiredTextRefs: Object.freeze([
          'did_authentication_unverified',
          'consent_middleware_unverified',
          'authority_middleware_unverified',
          'quorum_middleware_unverified',
          'gateway_service_unavailable',
        ]),
      },
      {
        pathRef: 'tests/node-receipt-sync.test.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_signature_missing',
          'query_receipt_id_missing',
          'authority_permission_missing',
        ]),
      },
    ]),
  },
  {
    id: 'MAC-002',
    contextText:
      'It cannot mint, cache, simulate, or override consent, authority, quorum, provenance, root authority, or Decision Forum outcomes outside Exochain enforcement.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze([
          '_local_simulation_forbidden',
          '_cached_outcome_forbidden',
          '_override_forbidden',
        ]),
      },
      {
        pathRef: 'src/gateway-call-path.mjs',
        requiredTextRefs: Object.freeze([
          'replayBlocks',
          'cachedOutcome',
          'cacheHit',
          'overrideUsed',
          'overrideApplied',
        ]),
      },
      {
        pathRef: 'src/production-claim-lifting.mjs',
        requiredTextRefs: Object.freeze([
          'adapter_simulated_outcome_possible',
          'adapter_cached_outcome_possible',
          'adapter_override_possible',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-fail-closed.test.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_local_simulation_forbidden',
          'receipt_cached_outcome_forbidden',
          'gateway_cached_outcome_forbidden',
          'decision_forum_override_forbidden',
        ]),
      },
      {
        pathRef: 'tests/gateway-call-path.test.mjs',
        requiredTextRefs: Object.freeze([
          'gateway_route_cached_outcome_forbidden',
          'gateway_route_override_forbidden',
        ]),
      },
      {
        pathRef: 'tests/production-claim-lifting.test.mjs',
        requiredTextRefs: Object.freeze([
          'adapter_simulated_outcome_possible',
          'adapter_cached_outcome_possible',
          'adapter_override_possible',
        ]),
      },
    ]),
  },
  {
    id: 'MAC-003',
    contextText:
      'It never writes raw PHI, PII, sponsor-confidential, privileged, or source document content into receipts, anchors, DAG payloads, telemetry, health, logs, debug endpoints, or exported diligence bundles.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_payload_disclosure',
          'gateway_payload_disclosure',
          'decision_forum_payload_disclosure',
          'receipt_observability_payload_disclosure',
        ]),
      },
      {
        pathRef: 'src/privacy-fixture-boundary.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_anchor',
          'dag_payload',
          'telemetry_event',
          'health_response',
          'debug_response',
          'export_manifest',
        ]),
      },
      {
        pathRef: 'src/diligence-exports.mjs',
        requiredTextRefs: Object.freeze([
          'rawexport',
          'sponsor_cro_diligence_export',
          'protectedContentExcluded',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-fail-closed.test.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_payload_disclosure',
          'gateway_payload_disclosure',
          'decision_forum_payload_disclosure',
          'receipt_observability_payload_disclosure',
        ]),
      },
      {
        pathRef: 'tests/privacy-fixture-boundary.test.mjs',
        requiredTextRefs: Object.freeze([
          'debug_response',
          'health_response',
          'telemetry_event',
          'export_manifest',
        ]),
      },
      {
        pathRef: 'tests/diligence-exports.test.mjs',
        requiredTextRefs: Object.freeze([
          'protected content',
          'hash-only',
          'trustState',
        ]),
      },
    ]),
  },
  {
    id: 'MAC-004',
    contextText:
      'It records operational database state separately from immutable Exochain receipts.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/audit-event-receipts.mjs',
        requiredTextRefs: Object.freeze([
          'cybermedica.operational_audit_record.v1',
          'operationalStateMutable',
          'immutableReceipt',
          'immutableAuditReceipt',
          'externalTrustReceipt',
        ]),
      },
      {
        pathRef: 'src/node-receipt-sync.mjs',
        requiredTextRefs: Object.freeze([
          'node_receipt_sync',
          'receiptStoreRef',
          'receiptSignatureVerified',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/audit-event-receipts.test.mjs',
        requiredTextRefs: Object.freeze([
          'operationalStateMutable',
          'immutableReceipt',
          'immutableAuditReceipt',
          'externalTrustReceipt',
        ]),
      },
      {
        pathRef: 'tests/node-receipt-sync.test.mjs',
        requiredTextRefs: Object.freeze([
          'receiptStoreRef',
          'receiptSignatureVerified',
          'node_receipt_sync',
        ]),
      },
    ]),
  },
  {
    id: 'MAC-005',
    contextText:
      'It includes source path, primitive, receipt path, test id, and PRD id for every trust claim.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/requirement-traceability.mjs',
        requiredTextRefs: Object.freeze([
          'requirement_source_ref_absent',
          'requirement_test_refs_absent',
          'requirement_exochain_primitives_absent',
          'requirement_adapter_boundary_absent',
          'requirementIds',
        ]),
      },
      {
        pathRef: 'src/service-contract-publication.mjs',
        requiredTextRefs: Object.freeze([
          'sourcePrdRef',
          'lastTestCommandRefs',
          'contractRows',
          'evidence_receipt_contract',
        ]),
      },
      {
        pathRef: 'src/trust-state-view.mjs',
        requiredTextRefs: Object.freeze([
          'Verified Exochain receipt path',
          'production trust claim',
          'source',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/requirement-traceability.test.mjs',
        requiredTextRefs: Object.freeze([
          'sourceRef',
          'testRefs',
          'exochainPrimitiveRefs',
          'adapterBoundaryRefs',
          'requirementId',
        ]),
      },
      {
        pathRef: 'tests/service-contract-publication.test.mjs',
        requiredTextRefs: Object.freeze([
          'sourcePrdRef',
          'lastTestCommandRefs',
          'evidence_receipt_contract',
        ]),
      },
      {
        pathRef: 'tests/trust-state-view.test.mjs',
        requiredTextRefs: Object.freeze(['receiptPath', 'canShowProductionTrustClaim', 'TrustState']),
      },
    ]),
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

function evaluateTextRefs(rootDir, requirementId, contract, kind) {
  const source = readProjectFile(rootDir, contract.pathRef);
  if (source === null) {
    return [
      {
        ruleId: `adapter_contract_${kind}_file_absent`,
        requirementId,
        pathRef: contract.pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return contract.requiredTextRefs
    .filter((requiredTextRef) => !source.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId: `adapter_contract_${kind}_text_absent`,
      requirementId,
      pathRef: contract.pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contextFindings(integrationMapText) {
  if (integrationMapText === null) {
    return [
      {
        ruleId: 'adapter_contract_register_file_absent',
        requirementId: null,
        pathRef: INTEGRATION_MAP_REF,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.filter(
    (requirement) => !integrationMapText.includes(requirement.contextText),
  ).map((requirement) => ({
    ruleId: 'adapter_contract_requirement_text_absent',
    requirementId: requirement.id,
    pathRef: INTEGRATION_MAP_REF,
    requiredTextRef: requirement.contextText,
    metadataOnly: true,
  }));
}

function compareFindings(left, right) {
  const requirementCompare = String(left.requirementId).localeCompare(String(right.requirementId));
  if (requirementCompare !== 0) {
    return requirementCompare;
  }
  const pathCompare = String(left.pathRef).localeCompare(String(right.pathRef));
  if (pathCompare !== 0) {
    return pathCompare;
  }
  const textCompare = String(left.requiredTextRef).localeCompare(String(right.requiredTextRef));
  if (textCompare !== 0) {
    return textCompare;
  }
  return left.ruleId.localeCompare(right.ruleId);
}

export function scanMinimumAdapterContractCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const integrationMapText = readProjectFile(rootDir, INTEGRATION_MAP_REF);
  const checkedSourceRefs = uniqueSorted(
    EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.flatMap((requirement) =>
      requirement.sourceContracts.map((contract) => contract.pathRef),
    ),
  );
  const checkedTestRefs = uniqueSorted(
    EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.flatMap((requirement) =>
      requirement.testContracts.map((contract) => contract.pathRef),
    ),
  );
  const findings = [
    ...contextFindings(integrationMapText),
    ...EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.flatMap((requirement) => [
      ...requirement.sourceContracts.flatMap((contract) =>
        evaluateTextRefs(rootDir, requirement.id, contract, 'source'),
      ),
      ...requirement.testContracts.flatMap((contract) =>
        evaluateTextRefs(rootDir, requirement.id, contract, 'test'),
      ),
    ]),
  ].sort(compareFindings);

  return {
    schema: 'cybermedica.source_adapter_contract_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-adapter-contract-guard',
    scannerVersionHash: sha256Hex(
      EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.map((requirement) => `${requirement.id}:${requirement.contextText}`).join(
        '|',
      ),
    ),
    integrationMapRef: INTEGRATION_MAP_REF,
    minimumAdapterRequirementIds: EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.map((requirement) => requirement.id),
    minimumAdapterRequirementCount: EXPECTED_MINIMUM_ADAPTER_REQUIREMENTS.length,
    checkedSourceRefs,
    checkedTestRefs,
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
  const report = scanMinimumAdapterContractCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
