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

const REQUIRED_DIMENSIONS = [
  'cro_portfolios',
  'decision_records',
  'evidence_volumes',
  'networks',
  'sites',
  'sponsors',
  'studies',
];

const REQUIRED_CONTROL_FAMILIES = [
  'access_policy_partitioning',
  'archive_retention_partitioning',
  'backpressure',
  'bulk_import_throttling',
  'decision_queue_sharding',
  'evidence_index_partitioning',
  'pagination_cursoring',
];

const REQUIRED_MONITORING_SIGNALS = [
  'api_request_queue',
  'decision_queue_depth',
  'evidence_ingestion_backlog',
  'export_job_backlog',
  'portfolio_dashboard_latency',
  'receipt_write_latency',
];

async function loadScalabilityCapacity() {
  try {
    return await import('../src/scalability-capacity.mjs');
  } catch (error) {
    assert.fail(`CyberMedica scalability capacity module must exist and load: ${error.message}`);
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

function scopeDimension(dimension, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  return {
    dimension,
    scopeRef: `scope-${dimension}`,
    inventoryHash: hashes[index],
    accessPolicyHash: hashes[(index + 1) % hashes.length],
    tenantPartitioned: true,
    metadataOnly: true,
  };
}

function operatingLimit(dimension, index) {
  return {
    dimension,
    hardLimit: [40, 900000, 4000000, 12, 350, 80, 1200][index],
    warningBasisPoints: 7000,
    criticalBasisPoints: 9000,
    scaleActionRef: `scale-action-${dimension}`,
    ownerRoleRef: dimension === 'cro_portfolios' ? 'cro_portfolio_manager' : 'quality_manager',
    failClosedWhenExceeded: true,
    metadataOnly: true,
  };
}

function workloadForecast(dimension, index) {
  return {
    dimension,
    currentCount: [5, 180000, 1200000, 2, 75, 12, 225][index],
    projectedCount: [12, 420000, 2300000, 5, 160, 25, 500][index],
    peakCount: [18, 720000, 3200000, 7, 230, 42, 850][index],
    forecastWindowDays: 180,
    evidenceHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_A, DIGEST_B, DIGEST_C][index],
    metadataOnly: true,
  };
}

function capacityControl(controlFamily, index) {
  const hashes = [DIGEST_F, DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A, DIGEST_1];
  return {
    controlFamily,
    controlRef: `capacity-control-${controlFamily}`,
    status: 'approved',
    evidenceHash: hashes[index],
    testedAtHlc: { physicalMs: 1796610200000 + index, logical: 0 },
    ownerRoleRef: 'platform_operator',
    metadataOnly: true,
  };
}

function monitoringSignal(signalFamily, index) {
  return {
    signalFamily,
    signalRef: `monitor-${signalFamily}`,
    status: 'passing',
    thresholdBasisPoints: signalFamily === 'api_request_queue' ? 7500 : 8000,
    currentBasisPoints: [3200, 4100, 3800, 2600, 4500, 3300][index],
    observedAtHlc: { physicalMs: 1796610500000 + index, logical: 0 },
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index],
    metadataOnly: true,
  };
}

function scalabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:capacity-governor-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'platform_operator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['scalability_capacity_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    scalePlan: {
      planRef: 'scale-plan-alpha',
      planVersion: 'v1',
      schemaVersion: 'cybermedica.scalability_capacity.v1',
      status: 'approved',
      tenantConfigurationRef: 'tenant-config-site-alpha@v1',
      availabilityReadinessRef: 'availability-readiness-alpha@v1',
      capacityModelHash: DIGEST_B,
      loadTestEvidenceHash: DIGEST_C,
      partitionStrategyHash: DIGEST_D,
      productionTrustClaim: false,
      metadataOnly: true,
    },
    governanceReview: {
      status: 'approved',
      reviewerDid: 'did:exo:quality-director-alpha',
      approvedAtHlc: { physicalMs: 1796610000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796610600000, logical: 0 },
      reviewEvidenceHash: DIGEST_E,
      quorumVerified: true,
      aiFinalAuthorityRejected: true,
    },
    scopeDimensions: REQUIRED_DIMENSIONS.map(scopeDimension).reverse(),
    operatingLimits: REQUIRED_DIMENSIONS.map(operatingLimit).reverse(),
    workloadForecasts: REQUIRED_DIMENSIONS.map(workloadForecast).reverse(),
    capacityControls: REQUIRED_CONTROL_FAMILIES.map(capacityControl).reverse(),
    monitoringSignals: REQUIRED_MONITORING_SIGNALS.map(monitoringSignal).reverse(),
    degradationPlan: {
      planHash: DIGEST_F,
      failClosedOnLimitExceeded: true,
      writeThrottlingPolicyHash: DIGEST_1,
      readOnlyModePolicyHash: DIGEST_2,
      auditTrailPreserved: true,
      decisionRecordsPreserved: true,
      participantSafetyBypassForbidden: true,
      testedAtHlc: { physicalMs: 1796610400000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      evidenceRefs: ['capacity-model-hash', 'load-test-evidence-hash'],
      reasoningSummaryHash: DIGEST_3,
      confidenceBasisPoints: 7900,
      limitationHashes: [DIGEST_4],
      unresolvedAssumptionHashes: [DIGEST_5],
      recommendedHumanReviewerDids: ['did:exo:quality-director-alpha'],
    },
    custodyDigest: DIGEST_4,
  };

  return mergeDeep(base, overrides);
}

test('scalability capacity creates deterministic NFR-009 inactive receipts', async () => {
  const { evaluateScalabilityCapacity } = await loadScalabilityCapacity();

  const resultA = evaluateScalabilityCapacity(scalabilityInput());
  const resultB = evaluateScalabilityCapacity(scalabilityInput({
    scopeDimensions: REQUIRED_DIMENSIONS.map(scopeDimension),
    capacityControls: REQUIRED_CONTROL_FAMILIES.map(capacityControl),
    monitoringSignals: REQUIRED_MONITORING_SIGNALS.map(monitoringSignal),
  }));

  assert.equal(resultA.permitted, true);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.capacityRecord.schema, 'cybermedica.scalability_capacity_record.v1');
  assert.equal(resultA.capacityRecord.status, 'approved');
  assert.equal(resultA.capacityRecord.trustState, 'inactive');
  assert.equal(resultA.capacityRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.capacityRecord.dimensionCoverage, REQUIRED_DIMENSIONS);
  assert.deepEqual(resultA.capacityRecord.controlCoverage, REQUIRED_CONTROL_FAMILIES);
  assert.deepEqual(resultA.capacityRecord.monitoringCoverage, REQUIRED_MONITORING_SIGNALS);
  assert.equal(resultA.capacityRecord.utilizationByDimension.sites.peakBasisPoints, 6571);
  assert.equal(resultA.capacityRecord.utilizationByDimension.evidence_volumes.peakBasisPoints, 8000);
  assert.equal(resultA.capacityRecord.highestPeakBasisPoints, 8000);
  assert.deepEqual(resultA.capacityRecord.alertStates, [
    'decision_records:warning',
    'evidence_volumes:warning',
    'studies:warning',
  ]);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'scalability_capacity');
  assert.equal(resultA.receipt.anchorPayload.classification, 'restricted_metadata_only');
  assert.equal(resultA.capacityRecord.capacityHash, resultB.capacityRecord.capacityHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('scalability capacity fails closed for missing coverage and exceeded operating limits', async () => {
  const { evaluateScalabilityCapacity } = await loadScalabilityCapacity();

  const absent = evaluateScalabilityCapacity({});

  assert.equal(absent.permitted, false);
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('scale_plan_ref_absent'));
  assert.ok(absent.reasons.includes('scope_dimensions_absent'));
  assert.ok(absent.reasons.includes('operating_limits_absent'));
  assert.ok(absent.reasons.includes('workload_forecasts_absent'));
  assert.ok(absent.reasons.includes('capacity_controls_absent'));
  assert.ok(absent.reasons.includes('monitoring_signals_absent'));
  assert.ok(absent.reasons.includes('governance_review_not_approved'));
  assert.equal(absent.capacityRecord, null);
  assert.equal(absent.receipt, null);

  const result = evaluateScalabilityCapacity(scalabilityInput({
    scopeDimensions: REQUIRED_DIMENSIONS.filter((dimension) => dimension !== 'sponsors').map(scopeDimension),
    operatingLimits: REQUIRED_DIMENSIONS.map((dimension, index) => (
      dimension === 'evidence_volumes'
        ? { ...operatingLimit(dimension, index), hardLimit: 2500000, failClosedWhenExceeded: false }
        : operatingLimit(dimension, index)
    )),
    workloadForecasts: REQUIRED_DIMENSIONS.map((dimension, index) => (
      dimension === 'decision_records'
        ? { ...workloadForecast(dimension, index), peakCount: 920000 }
        : workloadForecast(dimension, index)
    )),
    capacityControls: REQUIRED_CONTROL_FAMILIES.filter((family) => family !== 'backpressure').map(capacityControl),
    governanceReview: {
      quorumVerified: false,
    },
  }));

  assert.equal(result.permitted, false);
  assert.ok(result.reasons.includes('required_scope_dimension_missing:sponsors'));
  assert.ok(result.reasons.includes('required_capacity_control_missing:backpressure'));
  assert.ok(result.reasons.includes('capacity_limit_exceeded:evidence_volumes'));
  assert.ok(result.reasons.includes('limit_fail_closed_missing:evidence_volumes'));
  assert.ok(result.reasons.includes('critical_capacity_requires_governed_scale_action:decision_records'));
  assert.ok(result.reasons.includes('governance_quorum_unverified'));
  assert.equal(result.capacityRecord, null);
  assert.equal(result.receipt, null);
});

test('scalability capacity enforces HLC ordering monitoring and no-AI governance', async () => {
  const { evaluateScalabilityCapacity } = await loadScalabilityCapacity();

  const noAi = evaluateScalabilityCapacity(scalabilityInput({
    aiAssistance: { used: false },
  }));

  assert.equal(noAi.permitted, true);
  assert.equal(noAi.capacityRecord.aiAssistance.used, false);
  assert.equal(noAi.capacityRecord.aiAssistance.finalAuthority, false);

  const malformedClock = evaluateScalabilityCapacity(scalabilityInput({
    governanceReview: {
      approvedAtHlc: { physicalMs: 1796610000000, logical: -1 },
    },
  }));

  assert.equal(malformedClock.permitted, false);
  assert.ok(malformedClock.reasons.includes('governance_approval_time_invalid'));

  const unsafeOrdering = evaluateScalabilityCapacity(scalabilityInput({
    degradationPlan: {
      testedAtHlc: { physicalMs: 1796609999999, logical: 0 },
    },
    monitoringSignals: REQUIRED_MONITORING_SIGNALS.map((signal, index) => (
      signal === 'receipt_write_latency'
        ? { ...monitoringSignal(signal, index), status: 'degraded', currentBasisPoints: 8800 }
        : monitoringSignal(signal, index)
    )),
  }));

  assert.equal(unsafeOrdering.permitted, false);
  assert.ok(unsafeOrdering.reasons.includes('degradation_test_before_governance_approval'));
  assert.ok(unsafeOrdering.reasons.includes('monitoring_signal_not_passing:receipt_write_latency'));
  assert.ok(unsafeOrdering.reasons.includes('monitoring_signal_over_threshold:receipt_write_latency'));

  const sameTickEqual = evaluateScalabilityCapacity(scalabilityInput({
    degradationPlan: {
      testedAtHlc: { physicalMs: 1796610000000, logical: 0 },
    },
  }));

  assert.equal(sameTickEqual.permitted, false);
  assert.ok(sameTickEqual.reasons.includes('degradation_test_before_governance_approval'));

  const sameTickAdvancing = evaluateScalabilityCapacity(scalabilityInput({
    degradationPlan: {
      testedAtHlc: { physicalMs: 1796610000000, logical: 1 },
    },
    governanceReview: {
      approvedAtHlc: { physicalMs: 1796610000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796610000000, logical: 3 },
    },
    monitoringSignals: REQUIRED_MONITORING_SIGNALS.map((signal, index) => ({
      ...monitoringSignal(signal, index),
      observedAtHlc: { physicalMs: 1796610000000, logical: 2 + index },
    })),
  }));

  assert.equal(sameTickAdvancing.permitted, true);
});

test('scalability capacity rejects raw workload content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateScalabilityCapacity } = await loadScalabilityCapacity();

  assert.throws(
    () => evaluateScalabilityCapacity(scalabilityInput({
      workloadForecasts: [
        {
          ...workloadForecast('sites', 4),
          rawWorkloadPayload: 'participant Jane Example across site cohort',
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateScalabilityCapacity(scalabilityInput({
      scalePlan: {
        apiKey: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateScalabilityCapacity(scalabilityInput({
      scalePlan: {
        rawCapacityPayload: [false, 1],
      },
    })),
    ProtectedContentError,
  );

  const inertSecretMarker = evaluateScalabilityCapacity(scalabilityInput({
    scalePlan: {
      apiKey: false,
    },
  }));

  assert.equal(inertSecretMarker.permitted, true);
});
