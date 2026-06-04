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

const ADJACENT_SURFACE_DECISION_REGISTER_REF = 'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md';

const EXPECTED_ADJACENT_SURFACE_DECISIONS = Object.freeze([
  {
    id: 'ASD-001',
    contextText: 'CyberMedica remains adjacent to Exochain core.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/service-contract-publication.mjs',
        requiredTextRefs: Object.freeze(['adjacent_surface', 'exochainSourceReadOnly', 'exochainProductionClaim: false']),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/service-contract-publication.test.mjs',
        requiredTextRefs: Object.freeze([
          'service_contracts_publishable_inactive_trust',
          'service_contract_publication',
          'exochainProductionClaim',
        ]),
      },
    ]),
  },
  {
    id: 'ASD-002',
    contextText: 'Exochain repository is read-only for this pass.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ci-cd-quality-gates.mjs',
        requiredTextRefs: Object.freeze([
          'noExochainSourceModified',
          'source_guard_exochain_source_modified',
          'exochainSourceExcluded',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ci-cd-quality-gates.test.mjs',
        requiredTextRefs: Object.freeze(['noExochainSourceModified', 'exochainSourceExcluded', 'pathClassificationUpdated']),
      },
    ]),
  },
  {
    id: 'ASD-003',
    contextText: 'CyberMedica may develop service contracts before root activation.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/service-contract-publication.mjs',
        requiredTextRefs: Object.freeze([
          'baseline_service_contracts',
          'publication_policy_inactive_trust_gate_absent',
          'service_contracts_publishable_inactive_trust',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/service-contract-publication.test.mjs',
        requiredTextRefs: Object.freeze([
          'inactive_trust_state',
          'service_contracts_publishable_inactive_trust',
          'node --test tests/service-contract-publication.test.mjs',
        ]),
      },
    ]),
  },
  {
    id: 'ASD-004',
    contextText: 'Root-backed production trust claims are inactive until root bootstrap evidence is verified.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/root-trust-registry.mjs',
        requiredTextRefs: Object.freeze(['root_bundle_provider', 'root_certifier_inactive', 'exochainProductionClaim: false']),
      },
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze(['root_bundle_absent', 'root_threshold_signature_absent', 'root_verifier_pending']),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/root-trust-registry.test.mjs',
        requiredTextRefs: Object.freeze(['root trust bundle provider stays inactive', 'root_bundle_provider_endpoint_absent']),
      },
      {
        pathRef: 'tests/production-trust-activation.test.mjs',
        requiredTextRefs: Object.freeze(['production Exochain trust claims remain inactive', 'root_verifier_pending', 'exochainProductionClaim']),
      },
    ]),
  },
  {
    id: 'ASD-005',
    contextText: 'CyberMedica must use Exochain primitives only through verified adapters.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze([
          'gateway_adapter_unverified',
          'receipt_path_unverified',
          '_local_simulation_forbidden',
          '_cached_outcome_forbidden',
          '_override_forbidden',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-fail-closed.test.mjs',
        requiredTextRefs: Object.freeze([
          'gateway_service_unavailable',
          'receipt_service_unavailable',
          'gateway_cached_outcome_forbidden',
          'decision_forum_override_forbidden',
        ]),
      },
    ]),
  },
  {
    id: 'ASD-006',
    contextText: 'Decision Forum may support QMS gates only through adjudicated production paths.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/qms-control-approvals.mjs',
        requiredTextRefs: Object.freeze([
          'decision_forum_decision_id_absent',
          'decision_forum_workflow_receipt_absent',
          'human_governed',
        ]),
      },
      {
        pathRef: 'src/decision-forum-matters.mjs',
        requiredTextRefs: Object.freeze(['decision_forum_authority_missing', 'quorum_unverified', 'human_gate']),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/qms-control-approvals.test.mjs',
        requiredTextRefs: Object.freeze(['decision_forum_decision_id_absent', 'decision_forum_workflow_receipt_absent']),
      },
      {
        pathRef: 'tests/decision-forum-matters.test.mjs',
        requiredTextRefs: Object.freeze(['decision_forum_authority_missing', 'quorum_unverified', 'decision_forum_matter']),
      },
    ]),
  },
  {
    id: 'ASD-007',
    contextText: 'AI is assistant, not final authority.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ai-control-review.mjs',
        requiredTextRefs: Object.freeze([
          'ai_final_authority_forbidden',
          'human_review_policy_allows_ai_final_authority',
          'humanFinalAuthorityRequired: true',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ai-control-review.test.mjs',
        requiredTextRefs: Object.freeze(['ai_final_authority_forbidden', 'human_review_policy_allows_ai_final_authority']),
      },
    ]),
  },
  {
    id: 'ASD-008',
    contextText: 'CyberMedica must separate operational state from immutable receipts.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/audit-event-receipts.mjs',
        requiredTextRefs: Object.freeze(['operationalStateMutable', 'immutableReceipt', 'externalTrustReceipt']),
      },
      {
        pathRef: 'src/node-receipt-sync.mjs',
        requiredTextRefs: Object.freeze(['receiptStoreRef', 'receiptSignatureVerified', 'node_receipt_sync']),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/audit-event-receipts.test.mjs',
        requiredTextRefs: Object.freeze(['operationalStateMutable', 'immutableReceipt', 'externalTrustReceipt']),
      },
      {
        pathRef: 'tests/node-receipt-sync.test.mjs',
        requiredTextRefs: Object.freeze(['receiptStoreRef', 'receiptSignatureVerified', 'node_receipt_sync']),
      },
    ]),
  },
  {
    id: 'ASD-009',
    contextText:
      'CyberMedica must not expose Exochain root ceremony, raw admin governance, proof, CrossChecked anchor, or 0dentity behavioral axes as product features until verified.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/optional-trust-claim-guards.mjs',
        requiredTextRefs: Object.freeze(['PTAG-012', 'PTAG-014', 'policy_default_off_rule_absent', 'optional_capability_production_claim_forbidden']),
      },
      {
        pathRef: 'src/exochain-anchoring.mjs',
        requiredTextRefs: Object.freeze(['crossCheckedEnabled', 'crosschecked_anchor_forbidden_before_activation']),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/optional-trust-claim-guards.test.mjs',
        requiredTextRefs: Object.freeze(['zerodentity_behavioral_device_trust', 'commandbase_enforcement', 'disabled_default_off']),
      },
      {
        pathRef: 'tests/exochain-anchoring.test.mjs',
        requiredTextRefs: Object.freeze(['crosschecked_anchor_forbidden_before_activation']),
      },
    ]),
  },
  {
    id: 'ASD-010',
    contextText: "CyberMedica tests must exceed Exochain's general coverage bar at trust boundaries.",
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ci-cd-quality-gates.mjs',
        requiredTextRefs: Object.freeze([
          'minimumLineCoverageBasisPoints',
          'minimumTrustBoundaryCoverageBasisPoints',
          'trust_boundary_coverage_below_threshold',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ci-cd-quality-gates.test.mjs',
        requiredTextRefs: Object.freeze([
          'minimumLineCoverageBasisPoints: 9000',
          'trustBoundaryCoverageBasisPoints: 10000',
          'line_coverage_below_threshold',
        ]),
      },
      {
        pathRef: 'tests/source-guards.test.mjs',
        requiredTextRefs: Object.freeze(['--test-coverage-lines=90', 'guard:adjacent-decisions']),
      },
    ]),
  },
  {
    id: 'ASD-011',
    contextText: 'Final Exochain/root verification gates production activation, not baseline development.',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/adapter-activation-evidence.mjs',
        requiredTextRefs: Object.freeze([
          'root_bundle_production_claim_forbidden',
          'blocked_inactive_trust',
          'exochainProductionClaim: false',
        ]),
      },
      {
        pathRef: 'src/production-claim-lifting.mjs',
        requiredTextRefs: Object.freeze([
          'adapter_simulated_outcome_possible',
          'adapter_cached_outcome_possible',
          "allowed ? 'verified' : 'inactive'",
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-activation-evidence.test.mjs',
        requiredTextRefs: Object.freeze(['without lifting claims', 'blocked_inactive_trust', 'exochainProductionClaim']),
      },
      {
        pathRef: 'tests/production-claim-lifting.test.mjs',
        requiredTextRefs: Object.freeze(['adapter_simulated_outcome_possible', 'adapter_cached_outcome_possible', 'trustState']),
      },
    ]),
  },
]);

const ASD_ID_RE = /\bASD-\d{3}\b/gu;

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

function adjacentSurfaceDecisionIdsFromText(text) {
  return uniqueSorted([...text.matchAll(ASD_ID_RE)].map((match) => match[0]));
}

function decisionForId(decisionId) {
  return EXPECTED_ADJACENT_SURFACE_DECISIONS.find((decision) => decision.id === decisionId);
}

function registerFindings(registerText) {
  if (registerText === null) {
    return [
      {
        ruleId: 'adjacent_surface_decision_register_file_absent',
        decisionId: null,
        pathRef: ADJACENT_SURFACE_DECISION_REGISTER_REF,
        metadataOnly: true,
      },
    ];
  }

  const observedIds = adjacentSurfaceDecisionIdsFromText(registerText);
  const observedSet = new Set(observedIds);
  const expectedIds = EXPECTED_ADJACENT_SURFACE_DECISIONS.map((decision) => decision.id);
  const expectedSet = new Set(expectedIds);

  return [
    ...expectedIds.filter((decisionId) => !observedSet.has(decisionId)).map((decisionId) => ({
      ruleId: 'adjacent_surface_decision_register_id_absent',
      decisionId,
      pathRef: ADJACENT_SURFACE_DECISION_REGISTER_REF,
      metadataOnly: true,
    })),
    ...observedIds.filter((decisionId) => !expectedSet.has(decisionId)).map((decisionId) => ({
      ruleId: 'adjacent_surface_decision_register_id_unexpected',
      decisionId,
      pathRef: ADJACENT_SURFACE_DECISION_REGISTER_REF,
      metadataOnly: true,
    })),
    ...EXPECTED_ADJACENT_SURFACE_DECISIONS.filter((decision) => !registerText.includes(decision.contextText)).map(
      (decision) => ({
        ruleId: 'adjacent_surface_decision_context_text_absent',
        decisionId: decision.id,
        pathRef: ADJACENT_SURFACE_DECISION_REGISTER_REF,
        requiredTextRef: decision.contextText,
        metadataOnly: true,
      }),
    ),
  ];
}

function contractTextFindings(rootDir, decisionId, pathRef, requiredTextRefs, kind) {
  const text = readProjectFile(rootDir, pathRef);
  if (text === null) {
    return [
      {
        ruleId: `adjacent_surface_decision_${kind}_file_absent`,
        decisionId,
        pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return requiredTextRefs
    .filter((requiredTextRef) => !text.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId: `adjacent_surface_decision_${kind}_text_absent`,
      decisionId,
      pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contractFindings(rootDir) {
  return EXPECTED_ADJACENT_SURFACE_DECISIONS.flatMap((decision) => {
    const mappedDecision = decisionForId(decision.id);
    if (mappedDecision === undefined) {
      return [
        {
          ruleId: 'adjacent_surface_decision_contract_mapping_absent',
          decisionId: decision.id,
          pathRef: null,
          requiredTextRef: null,
          metadataOnly: true,
        },
      ];
    }
    return [
      ...mappedDecision.sourceContracts.flatMap((contract) =>
        contractTextFindings(rootDir, decision.id, contract.pathRef, contract.requiredTextRefs, 'source'),
      ),
      ...mappedDecision.testContracts.flatMap((contract) =>
        contractTextFindings(rootDir, decision.id, contract.pathRef, contract.requiredTextRefs, 'test'),
      ),
    ];
  });
}

function compareFindings(left, right) {
  const decisionCompare = String(left.decisionId).localeCompare(String(right.decisionId));
  if (decisionCompare !== 0) {
    return decisionCompare;
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

export function scanAdjacentSurfaceDecisionCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const registerText = readProjectFile(rootDir, ADJACENT_SURFACE_DECISION_REGISTER_REF);
  const adjacentSurfaceDecisionIds =
    registerText === null
      ? []
      : adjacentSurfaceDecisionIdsFromText(registerText).filter((decisionId) =>
          EXPECTED_ADJACENT_SURFACE_DECISIONS.some((decision) => decision.id === decisionId),
        );
  const checkedSourceRefs = uniqueSorted(
    EXPECTED_ADJACENT_SURFACE_DECISIONS.flatMap((decision) =>
      decision.sourceContracts.map((contract) => contract.pathRef),
    ),
  );
  const checkedTestRefs = uniqueSorted(
    EXPECTED_ADJACENT_SURFACE_DECISIONS.flatMap((decision) =>
      decision.testContracts.map((contract) => contract.pathRef),
    ),
  );
  const findings = [...registerFindings(registerText), ...contractFindings(rootDir)].sort(compareFindings);

  return {
    schema: 'cybermedica.source_adjacent_surface_decision_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-adjacent-surface-decision-guard',
    scannerVersionHash: sha256Hex(
      EXPECTED_ADJACENT_SURFACE_DECISIONS.map((decision) => {
        const sourceRefs = decision.sourceContracts.map((contract) => `${contract.pathRef}:${contract.requiredTextRefs.join(',')}`);
        const testRefs = decision.testContracts.map((contract) => `${contract.pathRef}:${contract.requiredTextRefs.join(',')}`);
        return `${decision.id}:${decision.contextText}:${sourceRefs.join(';')}:${testRefs.join(';')}`;
      }).join('|'),
    ),
    adjacentSurfaceDecisionRegisterRef: ADJACENT_SURFACE_DECISION_REGISTER_REF,
    adjacentSurfaceDecisionIds,
    adjacentSurfaceDecisionCount: adjacentSurfaceDecisionIds.length,
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
  const report = scanAdjacentSurfaceDecisionCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
