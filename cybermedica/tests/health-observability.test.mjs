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

const REQUIRED_HEALTH_CHECKS = [
  'decision_forum',
  'dependency_health',
  'privacy_boundary',
  'process_health',
  'receipt_queue',
  'root_bundle_provider',
  'trust_readiness',
];

const REQUIRED_OBSERVABILITY_SIGNALS = [
  'audit_event_flow',
  'decision_forum_latency',
  'dependency_status',
  'error_budget',
  'privacy_boundary',
  'process_uptime',
  'receipt_queue_depth',
  'trust_readiness_state',
];

const REQUIRED_TELEMETRY_BOUNDARIES = [
  'audit_log_redaction',
  'debug_output_redaction',
  'health_payload_redaction',
  'log_payload_redaction',
  'metric_label_minimization',
  'trace_payload_redaction',
];

const REQUIRED_INCIDENT_RUNBOOKS = [
  'adapter_degraded',
  'decision_forum_degraded',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
];

async function loadHealthObservability() {
  try {
    return await import('../src/health-observability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica health observability module must exist and load: ${error.message}`);
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

function healthCheck(checkFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  return {
    checkFamily,
    status: 'passing',
    endpointRef: `health-${checkFamily}`,
    evidenceHash: hashes[index],
    checkedByDid: 'did:exo:ops-observability-alpha',
    checkedAtHlc: { physicalMs: 1800700100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function observabilitySignal(signalFamily, index, overrides = {}) {
  const hashes = [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_A];
  return {
    signalFamily,
    status: 'active',
    evidenceHash: hashes[index],
    alertRuleHash: hashes[(index + 1) % hashes.length],
    thresholdBasisPoints: 9900,
    observedBasisPoints: signalFamily === 'error_budget' ? 9950 : 10000,
    evaluatedAtHlc: { physicalMs: 1800700200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function telemetryBoundary(boundaryFamily, index, overrides = {}) {
  const hashes = [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  return {
    boundaryFamily,
    status: 'verified',
    evidenceHash: hashes[index],
    payloadsRedacted: true,
    labelsMinimized: true,
    secretsExcluded: true,
    protectedContentExcluded: true,
    verifiedAtHlc: { physicalMs: 1800700300000, logical: index },
    metadataOnly: true,
    ...overrides,
  };
}

function incidentRunbook(runbookFamily, index, overrides = {}) {
  const hashes = [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    runbookFamily,
    runbookRef: `INCIDENT-${runbookFamily.toUpperCase()}`,
    runbookHash: hashes[index],
    status: 'approved',
    ownerDid: 'did:exo:incident-owner-alpha',
    backupOwnerDid: 'did:exo:incident-backup-alpha',
    escalationRouteHash: hashes[(index + 1) % hashes.length],
    lastDrillEvidenceHash: hashes[(index + 2) % hashes.length],
    reviewedAtHlc: { physicalMs: 1800700400000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function healthObservabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ops-observability-reviewer-alpha',
      kind: 'human',
      roleRefs: ['site_leader', 'quality_manager', 'ops_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['health_observability_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    observabilityPolicy: {
      policyRef: 'health-observability-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredHealthChecks: REQUIRED_HEALTH_CHECKS,
      requiredObservabilitySignals: REQUIRED_OBSERVABILITY_SIGNALS,
      requiredTelemetryBoundaries: REQUIRED_TELEMETRY_BOUNDARIES,
      requiredIncidentRunbooks: REQUIRED_INCIDENT_RUNBOOKS,
      healthAndTrustSeparated: true,
      noProtectedContentInSignals: true,
      noProductionTrustClaimWithoutActivation: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800700000000, logical: 0 },
    },
    service: {
      serviceRef: 'cybermedica-qms-api',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      environmentRef: 'staging-baseline',
      ownerDid: 'did:exo:ops-owner-alpha',
      backupOwnerDid: 'did:exo:ops-backup-alpha',
      healthEndpointRef: 'health-readiness-endpoint-alpha',
      telemetryDestinationRef: 'telemetry-destination-alpha',
      alertRouteRef: 'alert-route-alpha',
      dashboardRef: 'ops-dashboard-alpha',
      serviceMapHash: DIGEST_C,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    healthChecks: REQUIRED_HEALTH_CHECKS.map(healthCheck).reverse(),
    observabilitySignals: REQUIRED_OBSERVABILITY_SIGNALS.map(observabilitySignal).reverse(),
    telemetryBoundaries: REQUIRED_TELEMETRY_BOUNDARIES.map(telemetryBoundary).reverse(),
    incidentRunbooks: REQUIRED_INCIDENT_RUNBOOKS.map(incidentRunbook).reverse(),
    sloReview: {
      sloRef: 'slo-cybermedica-baseline',
      uptimeTargetBasisPoints: 9900,
      uptimeObservedBasisPoints: 9990,
      trustReadinessTargetBasisPoints: 9000,
      trustReadinessObservedBasisPoints: 9000,
      errorBudgetRemainingBasisPoints: 9950,
      reportHash: DIGEST_D,
      reviewedAtHlc: { physicalMs: 1800700500000, logical: 0 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['npm test', 'npm run quality', 'source guard', 'observability payload scan'],
      commandsPassed: true,
      sourceGuardPassed: true,
      payloadScanPassed: true,
      noExochainSourceModified: true,
      testEvidenceHash: DIGEST_E,
      recordedAtHlc: { physicalMs: 1800700600000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['quality_manager', 'ops_owner'],
      decision: 'accepted_inactive_trust',
      decisionHash: DIGEST_F,
      noProductionTrustClaim: true,
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800700700000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_1,
      limitationHashes: [DIGEST_2],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_3,
  };

  return mergeDeep(base, overrides);
}

test('health observability creates deterministic inactive Deployment Backlog receipts', async () => {
  const { evaluateHealthObservabilityReadiness } = await loadHealthObservability();

  const resultA = evaluateHealthObservabilityReadiness(healthObservabilityInput());
  const resultB = evaluateHealthObservabilityReadiness(
    healthObservabilityInput({
      healthChecks: REQUIRED_HEALTH_CHECKS.map(healthCheck),
      observabilitySignals: REQUIRED_OBSERVABILITY_SIGNALS.map(observabilitySignal),
      telemetryBoundaries: REQUIRED_TELEMETRY_BOUNDARIES.map(telemetryBoundary),
      incidentRunbooks: REQUIRED_INCIDENT_RUNBOOKS.map(incidentRunbook),
      observabilityPolicy: {
        requiredHealthChecks: [...REQUIRED_HEALTH_CHECKS].reverse(),
        requiredObservabilitySignals: [...REQUIRED_OBSERVABILITY_SIGNALS].reverse(),
        requiredTelemetryBoundaries: [...REQUIRED_TELEMETRY_BOUNDARIES].reverse(),
        requiredIncidentRunbooks: [...REQUIRED_INCIDENT_RUNBOOKS].reverse(),
      },
    }),
  );

  assert.equal(resultA.allowed, true);
  assert.equal(resultA.state, 'ready_inactive_trust');
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.healthObservabilityReady, true);
  assert.equal(resultA.productionTrustReady, false);
  assert.equal(resultA.readiness.healthCoverageBasisPoints, 10000);
  assert.equal(resultA.readiness.observabilityCoverageBasisPoints, 10000);
  assert.equal(resultA.readiness.telemetryBoundaryBasisPoints, 10000);
  assert.equal(resultA.readiness.incidentRunbookBasisPoints, 10000);
  assert.deepEqual(resultA.readiness.healthChecksCovered, REQUIRED_HEALTH_CHECKS);
  assert.deepEqual(resultA.readiness.observabilitySignalsCovered, REQUIRED_OBSERVABILITY_SIGNALS);
  assert.deepEqual(resultA.readiness.telemetryBoundariesCovered, REQUIRED_TELEMETRY_BOUNDARIES);
  assert.deepEqual(resultA.readiness.incidentRunbooksCovered, REQUIRED_INCIDENT_RUNBOOKS);
  assert.equal(resultA.readinessHash, resultB.readinessHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'health_observability_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
});

test('health observability fails closed for missing coverage unsafe claims and weak SLOs', async () => {
  const { evaluateHealthObservabilityReadiness } = await loadHealthObservability();

  const result = evaluateHealthObservabilityReadiness(
    healthObservabilityInput({
      service: {
        productionTrustClaim: true,
      },
      healthChecks: REQUIRED_HEALTH_CHECKS
        .filter((family) => family !== 'receipt_queue')
        .map(healthCheck),
      observabilitySignals: REQUIRED_OBSERVABILITY_SIGNALS
        .filter((family) => family !== 'error_budget')
        .map(observabilitySignal),
      telemetryBoundaries: REQUIRED_TELEMETRY_BOUNDARIES.map((family, index) =>
        telemetryBoundary(family, index, family === 'health_payload_redaction' ? { status: 'draft' } : {}),
      ),
      incidentRunbooks: REQUIRED_INCIDENT_RUNBOOKS
        .filter((family) => family !== 'root_bundle_unavailable')
        .map(incidentRunbook),
      sloReview: {
        uptimeObservedBasisPoints: 9800,
        trustReadinessObservedBasisPoints: 8000,
        errorBudgetRemainingBasisPoints: 5000,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.healthObservabilityReady, false);
  assert.equal(result.productionTrustReady, false);
  assert.ok(result.blockedBy.includes('production_trust_claim_forbidden'));
  assert.ok(result.blockedBy.includes('missing_health_check:receipt_queue'));
  assert.ok(result.blockedBy.includes('missing_observability_signal:error_budget'));
  assert.ok(result.blockedBy.includes('telemetry_boundary_not_verified:health_payload_redaction'));
  assert.ok(result.blockedBy.includes('missing_incident_runbook:root_bundle_unavailable'));
  assert.ok(result.blockedBy.includes('uptime_slo_breach'));
  assert.ok(result.blockedBy.includes('trust_readiness_slo_breach'));
  assert.ok(result.blockedBy.includes('error_budget_exhausted'));
  assert.equal(result.receipt, null);
});

test('health observability enforces authority HLC validation and advisory AI boundaries', async () => {
  const { evaluateHealthObservabilityReadiness } = await loadHealthObservability();

  const result = evaluateHealthObservabilityReadiness(
    healthObservabilityInput({
      targetTenantId: 'tenant-site-beta',
      actor: { kind: 'ai_agent' },
      authority: {
        valid: false,
        permissions: [],
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800700400000, logical: 0 },
        commandsPassed: false,
        payloadScanPassed: false,
        noExochainSourceModified: false,
      },
      humanReview: {
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1800700300000, logical: 0 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.ok(result.blockedBy.includes('tenant_boundary_violation'));
  assert.ok(result.blockedBy.includes('human_health_observability_reviewer_required'));
  assert.ok(result.blockedBy.includes('ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('authority_chain_invalid'));
  assert.ok(result.blockedBy.includes('health_observability_authority_missing'));
  assert.ok(result.blockedBy.includes('validation_commands_not_passed'));
  assert.ok(result.blockedBy.includes('validation_payload_scan_not_passed'));
  assert.ok(result.blockedBy.includes('validation_exochain_source_modified'));
  assert.ok(result.blockedBy.includes('validation_before_observability_evidence'));
  assert.ok(result.blockedBy.includes('human_review_before_validation'));
  assert.ok(result.blockedBy.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('production_trust_claim_forbidden'));
  assert.ok(result.blockedBy.includes('ai_recommendation_without_human_review'));
});

test('health observability rejects raw observability payloads protected content and secrets', async () => {
  const { ProtectedContentError, evaluateHealthObservabilityReadiness } = await loadHealthObservability();

  assert.throws(
    () =>
      evaluateHealthObservabilityReadiness(
        healthObservabilityInput({
          service: {
            rawHealthResponse: 'full response body and operational details',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateHealthObservabilityReadiness(
        healthObservabilityInput({
          observabilitySignals: [
            observabilitySignal('process_uptime', 0, {
              apiKey: 'cm-secret-value',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
});
