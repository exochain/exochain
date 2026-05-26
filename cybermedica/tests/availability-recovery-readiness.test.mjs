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
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_PROCEDURES = [
  'availability',
  'backup',
  'business_continuity',
  'disaster_recovery',
  'maintenance',
  'recovery',
];

const REQUIRED_MONITORING_SIGNALS = [
  'dependency_health',
  'process_uptime',
  'receipt_queue',
  'restore_point_age',
  'trust_readiness',
];

const REQUIRED_BACKUP_FAMILIES = [
  'audit_trails',
  'evidence_indexes',
  'metadata_records',
  'receipt_refs',
  'tenant_configs',
];

const REQUIRED_RESTORE_SCENARIOS = [
  'audit_record_restore',
  'evidence_index_restore',
  'metadata_database_restore',
  'receipt_queue_replay',
];

const REQUIRED_DR_SCENARIOS = [
  'identity_provider_degraded',
  'object_storage_unavailable',
  'primary_region_unavailable',
  'receipt_adapter_unavailable',
];

async function loadAvailabilityRecoveryReadiness() {
  try {
    return await import('../src/availability-recovery-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica availability recovery readiness module must exist and load: ${error.message}`);
  }
}

function procedure(procedureType, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    procedureType,
    procedureRef: `PROC-${procedureType.toUpperCase()}-001`,
    procedureHash: hashes[index],
    status: 'approved',
    ownerDid: 'did:exo:availability-owner-alpha',
    backupOwnerDid: 'did:exo:availability-backup-owner-alpha',
    reviewedAtHlc: { physicalMs: 1795400001000 + index, logical: 0 },
    evidenceHash: hashes[(index + 1) % hashes.length],
    metadataOnly: true,
  };
}

function monitoringSignal(signalType, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E];
  return {
    signalType,
    status: 'passing',
    evidenceHash: hashes[index],
    measuredAtHlc: { physicalMs: 1795400006000 + index, logical: 0 },
    metadataOnly: true,
  };
}

function restoreScenario(scenario, index) {
  const hashes = [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    scenario,
    evidenceRef: `RESTORE-${scenario.toUpperCase()}-001`,
    backupDigest: DIGEST_5,
    restoredArtifactHash: hashes[index],
    reconciliationHash: [DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_9][index],
    executedAtHlc: { physicalMs: 1795400010000 + index, logical: 0 },
    passed: true,
    dataIntegrityVerified: true,
    protectedContentExcluded: true,
    targetEnvironment: 'isolated_validation',
  };
}

function disasterScenario(scenario, index) {
  const hashes = [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E];
  return {
    scenario,
    evidenceHash: hashes[index],
    testedAtHlc: { physicalMs: 1795400015000 + index, logical: 0 },
    passed: true,
    failClosedObserved: true,
    rtoObservedMinutes: 45,
    rpoObservedMinutes: 10,
    noDataLossBeyondRpo: true,
  };
}

function availabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'availability_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['availability_readiness', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    service: {
      serviceRef: 'cybermedica-qms-site-alpha',
      serviceFamily: 'qms_core',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      ownerDid: 'did:exo:availability-owner-alpha',
      backupOwnerDid: 'did:exo:availability-backup-owner-alpha',
      escalationPathHash: DIGEST_B,
      rollbackDisablementHash: DIGEST_C,
      dependencyMapHash: DIGEST_D,
      maintenanceRunbookHash: DIGEST_E,
      configurationHash: DIGEST_F,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    availabilityPlan: {
      planRef: 'AVAIL-PLAN-SITE-ALPHA',
      planVersion: 'v1',
      approved: true,
      approvedByDid: 'did:exo:quality-director-alpha',
      approvedAtHlc: { physicalMs: 1795400000000, logical: 0 },
      approvalHash: DIGEST_1,
      rtoMinutes: 60,
      rpoMinutes: 15,
      maxTolerableDowntimeMinutes: 120,
      continuityRiskAssessmentHash: DIGEST_2,
      procedureRefs: REQUIRED_PROCEDURES.map(procedure).reverse(),
      metadataOnly: true,
    },
    monitoring: {
      monitorRef: 'AVAIL-MON-SITE-ALPHA',
      status: 'healthy',
      evaluatedAtHlc: { physicalMs: 1795400009000, logical: 0 },
      uptimeBasisPoints: 9995,
      thresholdBasisPoints: 9900,
      monitoringEvidenceHash: DIGEST_3,
      alertRouteHash: DIGEST_4,
      onCallScheduleHash: DIGEST_5,
      lastIncidentRunbookHash: DIGEST_6,
      signals: REQUIRED_MONITORING_SIGNALS.map(monitoringSignal).reverse(),
    },
    backup: {
      backupPolicyRef: 'BACKUP-POLICY-SITE-ALPHA',
      status: 'verified',
      scheduleHash: DIGEST_7,
      backupManifestHash: DIGEST_8,
      lastBackupDigest: DIGEST_5,
      lastSuccessfulBackupAtHlc: { physicalMs: 1795400008000, logical: 0 },
      restorePointAgeMinutes: 10,
      retentionDays: 2555,
      encryptedAtRest: true,
      offsiteCopy: true,
      immutableCopy: true,
      backupFamilies: REQUIRED_BACKUP_FAMILIES,
      metadataOnly: true,
      payloadsRemainExternal: true,
    },
    restoreTests: REQUIRED_RESTORE_SCENARIOS.map(restoreScenario).reverse(),
    continuity: {
      runbookRef: 'BCP-SITE-ALPHA',
      status: 'approved',
      continuityPlanHash: DIGEST_9,
      communicationsPlanHash: DIGEST_A,
      manualWorkaroundHash: DIGEST_B,
      onCallOwnerDid: 'did:exo:availability-owner-alpha',
      backupOwnerDid: 'did:exo:availability-backup-owner-alpha',
      criticalWorkflowRefs: ['consent_update', 'decision_forum', 'enrollment_gate', 'reporting', 'safety_event'],
      lastReviewedAtHlc: { physicalMs: 1795400007000, logical: 0 },
      metadataOnly: true,
    },
    disasterRecovery: {
      drPlanRef: 'DR-SITE-ALPHA',
      status: 'tested',
      failoverRunbookHash: DIGEST_C,
      failbackRunbookHash: DIGEST_D,
      recoverySiteRef: 'recovery-site-alpha',
      testedAtHlc: { physicalMs: 1795400018000, logical: 0 },
      drTestEvidenceHash: DIGEST_E,
      scenarios: REQUIRED_DR_SCENARIOS.map(disasterScenario).reverse(),
      metadataOnly: true,
    },
    auditTrail: {
      policyRef: 'AVAIL-AUDIT-POLICY-SITE-ALPHA',
      policyHash: DIGEST_F,
      appendOnly: true,
      tamperEvident: true,
      eventFamilies: ['backup', 'failover', 'incident', 'maintenance', 'monitoring', 'privileged_action', 'restore'],
      lastVerifiedAtHlc: { physicalMs: 1795400019000, logical: 0 },
    },
    privacyBoundary: {
      boundaryRef: 'AVAIL-PRIVACY-SITE-ALPHA',
      boundaryHash: DIGEST_1,
      receiptMetadataOnly: true,
      backupPayloadsStayExternal: true,
      restoreValidationUsesMetadataOnly: true,
      rawLogsExcluded: true,
      secretsExcluded: true,
      phiPiiExcludedFromReceipts: true,
      sponsorConfidentialMinimized: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      scopeHash: DIGEST_2,
      evidenceRefs: ['AVAIL-MON-SITE-ALPHA', 'RESTORE-METADATA_DATABASE_RESTORE-001'],
      limitationHashes: [DIGEST_3],
    },
    custodyDigest: DIGEST_4,
  };

  return deepMerge(base, overrides);
}

function deepMerge(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      deepMerge(base[key], overrides[key]),
    ]),
  );
}

test('availability recovery readiness creates deterministic NFR-003 inactive receipts', async () => {
  const { evaluateAvailabilityRecoveryReadiness } = await loadAvailabilityRecoveryReadiness();

  const resultA = evaluateAvailabilityRecoveryReadiness(availabilityInput());
  const resultB = evaluateAvailabilityRecoveryReadiness(
    availabilityInput({
      availabilityPlan: {
        procedureRefs: [...availabilityInput().availabilityPlan.procedureRefs].reverse(),
      },
      monitoring: {
        signals: [...availabilityInput().monitoring.signals].reverse(),
      },
      restoreTests: [...availabilityInput().restoreTests].reverse(),
      disasterRecovery: {
        scenarios: [...availabilityInput().disasterRecovery.scenarios].reverse(),
      },
      backup: {
        backupFamilies: [...REQUIRED_BACKUP_FAMILIES].reverse(),
      },
      auditTrail: {
        eventFamilies: [...availabilityInput().auditTrail.eventFamilies].reverse(),
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.availabilityRecord.availabilityReady, true);
  assert.equal(resultA.availabilityRecord.backupReady, true);
  assert.equal(resultA.availabilityRecord.recoveryReady, true);
  assert.equal(resultA.availabilityRecord.disasterRecoveryReady, true);
  assert.equal(resultA.availabilityRecord.metadataOnly, true);
  assert.equal(resultA.availabilityRecord.trustState, 'inactive');
  assert.equal(resultA.availabilityRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.availabilityRecord.procedureTypes, REQUIRED_PROCEDURES);
  assert.deepEqual(resultA.availabilityRecord.monitoringSignals, REQUIRED_MONITORING_SIGNALS);
  assert.deepEqual(resultA.availabilityRecord.backupFamilies, REQUIRED_BACKUP_FAMILIES);
  assert.deepEqual(resultA.availabilityRecord.restoreScenarios, REQUIRED_RESTORE_SCENARIOS);
  assert.deepEqual(resultA.availabilityRecord.disasterRecoveryScenarios, REQUIRED_DR_SCENARIOS);
  assert.equal(resultA.availabilityRecord.rtoMinutes, 60);
  assert.equal(resultA.availabilityRecord.rpoMinutes, 15);
  assert.equal(resultA.availabilityRecord.recordId, resultB.availabilityRecord.recordId);
  assert.equal(resultA.availabilityRecord.recordHash, resultB.availabilityRecord.recordHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'availability_recovery_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|raw backup|source document|api key/iu);
});

test('availability recovery readiness fails closed for incomplete backup restore and disaster evidence', async () => {
  const { evaluateAvailabilityRecoveryReadiness } = await loadAvailabilityRecoveryReadiness();
  const input = availabilityInput();
  input.actor.kind = 'ai_agent';
  input.service.backupOwnerDid = '';
  input.availabilityPlan.procedureRefs = input.availabilityPlan.procedureRefs.filter(
    (item) => item.procedureType !== 'disaster_recovery',
  );
  input.monitoring.status = 'degraded';
  input.monitoring.signals = input.monitoring.signals.filter((item) => item.signalType !== 'trust_readiness');
  input.backup.status = 'stale';
  input.backup.restorePointAgeMinutes = 20;
  input.backup.backupFamilies = input.backup.backupFamilies.filter((family) => family !== 'receipt_refs');
  input.restoreTests = input.restoreTests.filter((item) => item.scenario !== 'receipt_queue_replay');
  input.disasterRecovery.status = 'draft';
  input.disasterRecovery.scenarios = input.disasterRecovery.scenarios.filter(
    (item) => item.scenario !== 'object_storage_unavailable',
  );
  input.disasterRecovery.scenarios[0].passed = false;
  input.aiAssistance.finalAuthority = true;

  const result = evaluateAvailabilityRecoveryReadiness(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.availabilityRecord.availabilityReady, false);
  assert.equal(result.availabilityRecord.backupReady, false);
  assert.match(result.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(result.reasons.join('|'), /service_backup_owner_absent/);
  assert.match(result.reasons.join('|'), /availability_procedure_missing:disaster_recovery/);
  assert.match(result.reasons.join('|'), /monitoring_not_healthy/);
  assert.match(result.reasons.join('|'), /monitoring_signal_missing:trust_readiness/);
  assert.match(result.reasons.join('|'), /backup_not_verified/);
  assert.match(result.reasons.join('|'), /restore_point_exceeds_rpo/);
  assert.match(result.reasons.join('|'), /backup_family_missing:receipt_refs/);
  assert.match(result.reasons.join('|'), /restore_scenario_missing:receipt_queue_replay/);
  assert.match(result.reasons.join('|'), /disaster_recovery_not_tested/);
  assert.match(result.reasons.join('|'), /disaster_recovery_scenario_missing:object_storage_unavailable/);
  assert.match(result.reasons.join('|'), /disaster_recovery_scenario_not_passed/);
});

test('availability recovery readiness enforces RTO RPO HLC ordering and audit coverage', async () => {
  const { evaluateAvailabilityRecoveryReadiness } = await loadAvailabilityRecoveryReadiness();
  const sameTick = availabilityInput({
    availabilityPlan: {
      approvedAtHlc: { physicalMs: 1795400000000, logical: 0 },
    },
    monitoring: {
      evaluatedAtHlc: { physicalMs: 1795400009000, logical: 2 },
      signals: REQUIRED_MONITORING_SIGNALS.map((signal, index) => ({
        ...monitoringSignal(signal, index),
        measuredAtHlc: index === 0 ? { physicalMs: 1795400009000, logical: 2 } : { physicalMs: 1795400009000, logical: 0 },
      })),
    },
    backup: {
      lastSuccessfulBackupAtHlc: { physicalMs: 1795400009000, logical: 3 },
    },
    restoreTests: REQUIRED_RESTORE_SCENARIOS.map((scenario, index) => ({
      ...restoreScenario(scenario, index),
      executedAtHlc: { physicalMs: 1795400009000, logical: 4 + index },
    })),
    disasterRecovery: {
      testedAtHlc: { physicalMs: 1795400018000, logical: 1 },
      scenarios: REQUIRED_DR_SCENARIOS.map((scenario, index) => ({
        ...disasterScenario(scenario, index),
        testedAtHlc: { physicalMs: 1795400018000, logical: index + 2 },
      })),
    },
  });

  assert.equal(evaluateAvailabilityRecoveryReadiness(sameTick).decision, 'permitted');

  const invalid = availabilityInput();
  invalid.availabilityPlan.rtoMinutes = 60;
  invalid.availabilityPlan.rpoMinutes = 15;
  invalid.availabilityPlan.maxTolerableDowntimeMinutes = 30;
  invalid.availabilityPlan.procedureRefs[0].reviewedAtHlc = { physicalMs: 1795400000000, logical: -1 };
  invalid.monitoring.uptimeBasisPoints = 9800;
  invalid.monitoring.signals[0].measuredAtHlc = { physicalMs: 1795400010000, logical: 0 };
  invalid.restoreTests[0].executedAtHlc = { physicalMs: 1795400007000, logical: 0 };
  invalid.disasterRecovery.scenarios[0].rtoObservedMinutes = 90;
  invalid.disasterRecovery.scenarios[0].rpoObservedMinutes = 20;
  invalid.disasterRecovery.scenarios[1].noDataLossBeyondRpo = false;
  invalid.auditTrail.eventFamilies = ['backup'];

  const denied = evaluateAvailabilityRecoveryReadiness(invalid);

  assert.equal(denied.decision, 'denied');
  assert.match(denied.reasons.join('|'), /max_tolerable_downtime_below_rto/);
  assert.match(denied.reasons.join('|'), /availability_procedure_review_time_invalid/);
  assert.match(denied.reasons.join('|'), /uptime_below_threshold/);
  assert.match(denied.reasons.join('|'), /monitoring_signal_after_evaluation/);
  assert.match(denied.reasons.join('|'), /restore_executed_before_backup/);
  assert.match(denied.reasons.join('|'), /disaster_recovery_rto_exceeded/);
  assert.match(denied.reasons.join('|'), /disaster_recovery_rpo_exceeded/);
  assert.match(denied.reasons.join('|'), /disaster_recovery_data_loss_boundary_invalid/);
  assert.match(denied.reasons.join('|'), /audit_event_family_missing:restore/);
});

test('availability recovery readiness supports no AI assistance while preserving human readiness gates', async () => {
  const { evaluateAvailabilityRecoveryReadiness } = await loadAvailabilityRecoveryReadiness();
  const input = availabilityInput({
    aiAssistance: { used: false },
  });

  const result = evaluateAvailabilityRecoveryReadiness(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.availabilityRecord.aiAssisted, false);
  assert.equal(result.availabilityRecord.ownerDid, 'did:exo:availability-owner-alpha');
  assert.equal(result.availabilityRecord.backupOwnerDid, 'did:exo:availability-backup-owner-alpha');
});

test('availability recovery readiness rejects raw backup restore content and secrets', async () => {
  const { evaluateAvailabilityRecoveryReadiness, ProtectedContentError } = await loadAvailabilityRecoveryReadiness();
  const inertMarkers = availabilityInput();
  inertMarkers.backup.rawBackupPayload = [];
  inertMarkers.restoreTests[0].restoredDatabaseDump = false;
  inertMarkers.disasterRecovery.apiKey = {};

  assert.equal(evaluateAvailabilityRecoveryReadiness(inertMarkers).decision, 'permitted');

  const rawBackup = availabilityInput();
  rawBackup.backup.rawBackupPayload = 'patient Alice raw backup payload';

  assert.throws(() => evaluateAvailabilityRecoveryReadiness(rawBackup), ProtectedContentError);

  const secretInput = availabilityInput();
  secretInput.disasterRecovery.apiKey = 'cm_live_secret';

  assert.throws(() => evaluateAvailabilityRecoveryReadiness(secretInput), ProtectedContentError);

  const numericRawInput = availabilityInput();
  numericRawInput.restoreTests[0].restoredDatabaseDump = 42;

  assert.throws(() => evaluateAvailabilityRecoveryReadiness(numericRawInput), ProtectedContentError);
});
