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

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';

const REQUIRED_FAILURE_SCENARIOS = [
  'duplicate_submission',
  'integration_failure',
  'interrupted_upload',
  'partial_failure',
  'retry_scenario',
];

const REQUIRED_RECOVERY_CONTROLS = [
  'bounded_retry',
  'dead_letter_queue',
  'duplicate_submission_detector',
  'idempotency_key',
  'interrupted_upload_manifest',
  'reconciliation_job',
  'timeout_denial',
];

const REQUIRED_DEPENDENCY_FAMILIES = [
  'decision_forum',
  'exochain_gateway',
  'exochain_node_receipts',
  'integration_connector',
  'object_storage',
  'operational_database',
];

async function loadReliabilityReadiness() {
  try {
    return await import('../src/reliability-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica reliability readiness module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function failureScenario(scenario, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E];
  return {
    scenario,
    status: 'passed',
    evidenceRef: `rel-scenario-${scenario}`,
    evidenceHash: hashes[index],
    recoveryArtifactHash: hashes[(index + 1) % hashes.length],
    reconciliationEvidenceHash: hashes[(index + 2) % hashes.length],
    exercisedAtHlc: { physicalMs: 1800800100000, logical: index },
    failClosedObserved: true,
    idempotencyPreserved: true,
    noPayloadDisclosure: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function recoveryControl(controlFamily, index, overrides = {}) {
  const hashes = [DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    controlFamily,
    status: 'verified',
    evidenceHash: hashes[index],
    ownerDid: 'did:exo:reliability-owner-alpha',
    verifiedAtHlc: { physicalMs: 1800800200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dependencyRecovery(dependencyFamily, index, overrides = {}) {
  const hashes = [DIGEST_7, DIGEST_8, DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    dependencyFamily,
    status: 'verified',
    evidenceHash: hashes[index],
    responseMode: dependencyFamily === 'integration_connector' ? 'queue_and_reconcile' : 'fail_closed',
    timeoutDenied: true,
    staleResponseRejected: true,
    retryBounded: true,
    trustOutcomeNotOverridden: true,
    checkedAtHlc: { physicalMs: 1800800300000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function reliabilityReadinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ops-reliability-reviewer-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'ops_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['reliability_readiness_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    reliabilityPolicy: {
      policyRef: 'nfr-012-reliability-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredFailureScenarios: REQUIRED_FAILURE_SCENARIOS,
      requiredRecoveryControls: REQUIRED_RECOVERY_CONTROLS,
      requiredDependencyFamilies: REQUIRED_DEPENDENCY_FAMILIES,
      partialFailureMode: 'fail_closed',
      integrationFailureMode: 'queue_and_reconcile',
      interruptedUploadMode: 'resume_from_manifest',
      duplicateSubmissionMode: 'idempotent_reject',
      retryMode: 'bounded_idempotent_retry',
      retryBackoffStrategy: 'bounded_exponential',
      maxRetryCount: 5,
      evaluatedAtHlc: { physicalMs: 1800800000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    service: {
      serviceRef: 'cybermedica-qms-api',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      ownerDid: 'did:exo:ops-owner-alpha',
      backupOwnerDid: 'did:exo:ops-backup-alpha',
      runtimeTopologyHash: DIGEST_C,
      idempotencyKeyFormatHash: DIGEST_D,
      retryPolicyHash: DIGEST_E,
      reconciliationPolicyHash: DIGEST_F,
      queuePolicyHash: DIGEST_1,
      uploadManifestPolicyHash: DIGEST_2,
      metadataOnly: true,
      sourcePayloadsRemainExternal: true,
      productionTrustClaim: false,
    },
    failureScenarios: REQUIRED_FAILURE_SCENARIOS.map(failureScenario).reverse(),
    recoveryControls: REQUIRED_RECOVERY_CONTROLS.map(recoveryControl).reverse(),
    dependencyRecoveries: REQUIRED_DEPENDENCY_FAMILIES.map(dependencyRecovery).reverse(),
    operationsReview: {
      decision: 'accepted_inactive_trust',
      reviewedByDid: 'did:exo:quality-manager-alpha',
      reviewHash: DIGEST_3,
      reviewedAtHlc: { physicalMs: 1800800400000, logical: 0 },
      materialIncidentOpen: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      scopeHash: DIGEST_4,
      evidenceRefs: ['rel-scenario-partial_failure', 'rel-scenario-retry_scenario'],
      limitationHashes: [DIGEST_5],
    },
    custodyDigest: DIGEST_6,
  };
  return mergeDeep(base, overrides);
}

test('reliability readiness creates deterministic inactive NFR-012 receipts', async () => {
  const { evaluateReliabilityReadiness } = await loadReliabilityReadiness();

  const resultA = evaluateReliabilityReadiness(reliabilityReadinessInput());
  const resultB = evaluateReliabilityReadiness(
    reliabilityReadinessInput({
      reliabilityPolicy: {
        requiredFailureScenarios: [...REQUIRED_FAILURE_SCENARIOS].reverse(),
        requiredRecoveryControls: [...REQUIRED_RECOVERY_CONTROLS].reverse(),
        requiredDependencyFamilies: [...REQUIRED_DEPENDENCY_FAMILIES].reverse(),
      },
      failureScenarios: REQUIRED_FAILURE_SCENARIOS.map(failureScenario),
      recoveryControls: REQUIRED_RECOVERY_CONTROLS.map(recoveryControl),
      dependencyRecoveries: REQUIRED_DEPENDENCY_FAMILIES.map(dependencyRecovery),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.reliabilityReadiness.nfrId, 'NFR-012');
  assert.equal(resultA.reliabilityReadiness.ready, true);
  assert.equal(resultA.reliabilityReadiness.trustState, 'inactive');
  assert.equal(resultA.reliabilityReadiness.exochainProductionClaim, false);
  assert.deepEqual(resultA.reliabilityReadiness.failureScenarios, REQUIRED_FAILURE_SCENARIOS);
  assert.deepEqual(resultA.reliabilityReadiness.recoveryControls, REQUIRED_RECOVERY_CONTROLS);
  assert.deepEqual(resultA.reliabilityReadiness.dependencyFamilies, REQUIRED_DEPENDENCY_FAMILIES);
  assert.equal(resultA.reliabilityReadiness.readinessHash, resultB.reliabilityReadiness.readinessHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'reliability_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|source document|raw upload|api key/iu);
});

test('reliability readiness fails closed for missing failure coverage recovery controls and dependency evidence', async () => {
  const { evaluateReliabilityReadiness } = await loadReliabilityReadiness();

  const result = evaluateReliabilityReadiness(
    reliabilityReadinessInput({
      actor: { kind: 'ai_agent' },
      authority: { valid: false, permissions: [] },
      reliabilityPolicy: {
        status: 'draft',
        requiredRecoveryControls: REQUIRED_RECOVERY_CONTROLS.filter((item) => item !== 'dead_letter_queue'),
        maxRetryCount: 26,
        retryBackoffStrategy: 'unbounded',
        productionTrustClaim: true,
      },
      failureScenarios: REQUIRED_FAILURE_SCENARIOS.map(failureScenario).filter(
        (item) => item.scenario !== 'duplicate_submission',
      ),
      recoveryControls: REQUIRED_RECOVERY_CONTROLS.map(recoveryControl).filter(
        (item) => item.controlFamily !== 'dead_letter_queue',
      ),
      dependencyRecoveries: REQUIRED_DEPENDENCY_FAMILIES.map(dependencyRecovery).filter(
        (item) => item.dependencyFamily !== 'exochain_node_receipts',
      ),
      operationsReview: {
        decision: 'accepted_inactive_trust',
        materialIncidentOpen: true,
      },
      aiAssistance: {
        finalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.reliabilityReadiness.ready, false);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_invalid'));
  assert.ok(result.reasons.includes('reliability_policy_not_active'));
  assert.ok(result.reasons.includes('retry_count_invalid'));
  assert.ok(result.reasons.includes('retry_backoff_strategy_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('policy_recovery_control_missing:dead_letter_queue'));
  assert.ok(result.reasons.includes('failure_scenario_missing:duplicate_submission'));
  assert.ok(result.reasons.includes('recovery_control_missing:dead_letter_queue'));
  assert.ok(result.reasons.includes('dependency_recovery_missing:exochain_node_receipts'));
  assert.ok(result.reasons.includes('material_reliability_incident_open'));
});

test('reliability readiness enforces HLC ordering bounded retries and fail-closed dependencies', async () => {
  const { evaluateReliabilityReadiness } = await loadReliabilityReadiness();

  const sameTick = reliabilityReadinessInput({
    failureScenarios: [
      failureScenario('duplicate_submission', 0, { exercisedAtHlc: { physicalMs: 1800800000000, logical: 1 } }),
      ...REQUIRED_FAILURE_SCENARIOS.slice(1).map(failureScenario),
    ],
    recoveryControls: [
      recoveryControl('bounded_retry', 0, { verifiedAtHlc: { physicalMs: 1800800000000, logical: 2 } }),
      ...REQUIRED_RECOVERY_CONTROLS.slice(1).map(recoveryControl),
    ],
    dependencyRecoveries: [
      dependencyRecovery('decision_forum', 0, { checkedAtHlc: { physicalMs: 1800800000000, logical: 3 } }),
      ...REQUIRED_DEPENDENCY_FAMILIES.slice(1).map(dependencyRecovery),
    ],
    operationsReview: {
      reviewedAtHlc: { physicalMs: 1800800400000, logical: 1 },
    },
  });
  assert.equal(evaluateReliabilityReadiness(sameTick).decision, 'permitted');

  const result = evaluateReliabilityReadiness(
    reliabilityReadinessInput({
      reliabilityPolicy: {
        maxRetryCount: 0,
      },
      failureScenarios: [
        failureScenario('duplicate_submission', 0, {
          exercisedAtHlc: { physicalMs: 1800799999999, logical: 0 },
          failClosedObserved: false,
          idempotencyPreserved: false,
        }),
        ...REQUIRED_FAILURE_SCENARIOS.slice(1).map(failureScenario),
      ],
      dependencyRecoveries: [
        dependencyRecovery('decision_forum', 0, {
          checkedAtHlc: { physicalMs: 1800799999998, logical: 0 },
          timeoutDenied: false,
          trustOutcomeNotOverridden: false,
        }),
        ...REQUIRED_DEPENDENCY_FAMILIES.slice(1).map(dependencyRecovery),
      ],
      operationsReview: {
        reviewedAtHlc: { physicalMs: 1800800100000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('|'), /retry_count_invalid/);
  assert.match(result.reasons.join('|'), /failure_scenario_before_policy_evaluation:rel-scenario-duplicate_submission/);
  assert.match(result.reasons.join('|'), /failure_scenario_fail_closed_absent:duplicate_submission/);
  assert.match(result.reasons.join('|'), /failure_scenario_idempotency_absent:duplicate_submission/);
  assert.match(result.reasons.join('|'), /dependency_checked_before_policy_evaluation:decision_forum/);
  assert.match(result.reasons.join('|'), /dependency_timeout_denial_absent:decision_forum/);
  assert.match(result.reasons.join('|'), /dependency_trust_override_forbidden:decision_forum/);
  assert.match(result.reasons.join('|'), /operations_review_before_dependency_check:/);
});

test('reliability readiness rejects raw payloads protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateReliabilityReadiness } = await loadReliabilityReadiness();

  assert.throws(
    () =>
      evaluateReliabilityReadiness(
        reliabilityReadinessInput({
          failureScenarios: [
            failureScenario('duplicate_submission', 0, {
              rawUploadChunk: 'participant Alice source document body',
            }),
            ...REQUIRED_FAILURE_SCENARIOS.slice(1).map(failureScenario),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReliabilityReadiness(
        reliabilityReadinessInput({
          service: {
            apiKey: 'redacted-api-key-value',
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('reliability readiness handles absent collections as denial states without issuing receipts', async () => {
  const { evaluateReliabilityReadiness } = await loadReliabilityReadiness();

  const result = evaluateReliabilityReadiness(
    reliabilityReadinessInput({
      failureScenarios: [],
      recoveryControls: [],
      dependencyRecoveries: [],
      operationsReview: {
        decision: 'hold_for_reliability_gap',
      },
      aiAssistance: {
        used: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('failure_scenarios_absent'));
  assert.ok(result.reasons.includes('recovery_controls_absent'));
  assert.ok(result.reasons.includes('dependency_recoveries_absent'));
  assert.equal(result.reliabilityReadiness.aiAssisted, false);
});
