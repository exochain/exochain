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

const REQUIRED_CALIBRATION_DOMAINS = Object.freeze([
  'calibration_evidence',
  'calibration_schedule',
  'calibration_traceability',
  'check_before_use',
  'defect_reporting',
  'equipment_inventory',
  'maintenance_records',
  'quarantine_control',
  'return_to_service',
]);

async function loadEquipmentCalibrationReadiness() {
  try {
    return await import('../src/equipment-calibration-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica equipment-calibration-readiness module must exist and load: ${error.message}`);
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

function domainEvidence(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index % hashes.length],
    reviewedAtHlc: { physicalMs: 1803000020000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function equipmentRecord(overrides = {}) {
  return {
    equipmentRef: 'eq-ecg-alpha-001',
    equipmentType: 'ecg',
    manufacturerRef: 'mfg-ecg-alpha',
    serialNumberHash: DIGEST_A,
    protocolRef: 'protocol-cardiac-alpha',
    siteRef: 'site-alpha',
    locationRef: 'exam-room-alpha',
    status: 'active',
    calibrationRequired: true,
    calibrationFrequencyDays: 90,
    calibrationOwnerDid: 'did:exo:biomed-alpha',
    calibrationStandardTraceabilityHash: DIGEST_B,
    lastCalibrationAtHlc: { physicalMs: 1803000000000, logical: 0 },
    nextCalibrationDueHlc: { physicalMs: 1810000000000, logical: 0 },
    currentCalibrationEventRef: 'cal-event-alpha-001',
    checkBeforeUseRequired: true,
    currentCheckRecordRef: 'check-alpha-001',
    defectStatus: 'fit_for_use',
    quarantineStatus: 'not_quarantined',
    maintenanceRecordHash: DIGEST_C,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function calibrationEvent(overrides = {}) {
  return {
    eventRef: 'cal-event-alpha-001',
    equipmentRef: 'eq-ecg-alpha-001',
    performedAtHlc: { physicalMs: 1803000000000, logical: 1 },
    performedByDid: 'did:exo:biomed-alpha',
    result: 'passed',
    calibrationEvidenceHash: DIGEST_D,
    standardTraceabilityHash: DIGEST_B,
    certificateHash: DIGEST_E,
    nextDueAtHlc: { physicalMs: 1810000000000, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function checkRecord(overrides = {}) {
  return {
    checkRef: 'check-alpha-001',
    equipmentRef: 'eq-ecg-alpha-001',
    checkedAtHlc: { physicalMs: 1803000060000, logical: 0 },
    checkedByDid: 'did:exo:crc-alpha',
    result: 'passed',
    evidenceHash: DIGEST_F,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function defectQuarantineRecord(overrides = {}) {
  return {
    defectRef: 'defect-alpha-001',
    equipmentRef: 'eq-ecg-alpha-001',
    defectOpenedAtHlc: { physicalMs: 1803000030000, logical: 0 },
    defectEvidenceHash: DIGEST_A,
    severity: 'major',
    quarantineStatus: 'released',
    quarantinedAtHlc: { physicalMs: 1803000031000, logical: 0 },
    quarantineEvidenceHash: DIGEST_B,
    returnToServiceApproved: true,
    returnToServiceApprovedByDid: 'did:exo:facility-manager-alpha',
    returnToServiceEvidenceHash: DIGEST_C,
    returnedToServiceAtHlc: { physicalMs: 1803000040000, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:facility-manager-alpha',
      kind: 'human',
      roleRefs: ['facility_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_equipment_calibration', 'write'],
      authorityChainHash: DIGEST_A,
    },
    calibrationProgram: {
      programRef: 'equipment-calibration-program-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'active',
      requiredDomains: REQUIRED_CALIBRATION_DOMAINS,
      equipmentInventoryHash: DIGEST_B,
      calibrationScheduleHash: DIGEST_C,
      calibrationSopHash: DIGEST_D,
      defectQuarantineProcedureHash: DIGEST_E,
      returnToServiceProcedureHash: DIGEST_F,
      assessedAtHlc: { physicalMs: 1803000070000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    equipmentRecords: [equipmentRecord()],
    calibrationEvents: [calibrationEvent()],
    checkBeforeUseRecords: [checkRecord()],
    defectQuarantineRecords: [defectQuarantineRecord()],
    readinessControls: {
      domainEvidence: REQUIRED_CALIBRATION_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
      openDefectCount: 0,
      quarantinedEquipmentCount: 0,
      allRequiredEquipmentTraceable: true,
      allCurrentUseBlockedForDefects: true,
      maintenanceReviewHash: DIGEST_A,
      inventoryReconciliationHash: DIGEST_B,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      facilityManagerDid: 'did:exo:facility-manager-alpha',
      biomedicalReviewerDid: 'did:exo:biomed-alpha',
      decision: 'equipment_calibration_ready',
      reviewedAtHlc: { physicalMs: 1803000080000, logical: 0 },
      finalAuthority: 'human',
      aiFinalAuthority: false,
      evidenceBundleHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-equipment-calibration-alpha',
        workflowReceiptId: 'df-workflow-equipment-calibration-alpha',
      },
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('equipment calibration readiness creates deterministic inactive FR-035 receipts', async () => {
  const { evaluateEquipmentCalibrationReadiness } = await loadEquipmentCalibrationReadiness();

  const resultA = evaluateEquipmentCalibrationReadiness(readinessInput());
  const inputB = readinessInput();
  inputB.calibrationProgram.requiredDomains = [...inputB.calibrationProgram.requiredDomains].reverse();
  inputB.readinessControls.domainEvidence = [...inputB.readinessControls.domainEvidence].reverse();
  const resultB = evaluateEquipmentCalibrationReadiness(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.calibrationReadiness.readinessStatus, 'ready');
  assert.equal(resultA.calibrationReadiness.equipmentCount, 1);
  assert.equal(resultA.calibrationReadiness.calibrationRequiredCount, 1);
  assert.equal(resultA.calibrationReadiness.checkBeforeUseRequiredCount, 1);
  assert.equal(resultA.calibrationReadiness.openDefectCount, 0);
  assert.equal(resultA.calibrationReadiness.quarantinedEquipmentCount, 0);
  assert.deepEqual(resultA.calibrationReadiness.requiredDomains, REQUIRED_CALIBRATION_DOMAINS);
  assert.deepEqual(resultA.calibrationReadiness.coveredDomains, REQUIRED_CALIBRATION_DOMAINS);
  assert.equal(resultA.calibrationReadiness.aiFinalAuthority, false);
  assert.equal(resultA.calibrationReadiness.exochainProductionClaim, false);
  assert.equal(resultA.calibrationReadiness.containsProtectedContent, false);
  assert.equal(resultA.calibrationReadiness.readinessId, resultB.calibrationReadiness.readinessId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'equipment_calibration_readiness');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|serial number 123|raw equipment/iu);
});

test('equipment calibration readiness denies missing domains and stale calibration windows', async () => {
  const { evaluateEquipmentCalibrationReadiness } = await loadEquipmentCalibrationReadiness();

  const result = evaluateEquipmentCalibrationReadiness(
    readinessInput({
      calibrationProgram: {
        requiredDomains: REQUIRED_CALIBRATION_DOMAINS.filter((domainRef) => domainRef !== 'calibration_schedule'),
      },
      equipmentRecords: [
        equipmentRecord({
          nextCalibrationDueHlc: { physicalMs: 1803000070000, logical: 0 },
        }),
      ],
      calibrationEvents: [
        calibrationEvent({
          nextDueAtHlc: { physicalMs: 1809000000000, logical: 0 },
          standardTraceabilityHash: '',
        }),
      ],
      readinessControls: {
        domainEvidence: REQUIRED_CALIBRATION_DOMAINS.filter((domainRef) => domainRef !== 'calibration_evidence').map(
          (domainRef, index) => domainEvidence(domainRef, index),
        ),
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.calibrationReadiness.readinessStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /required_domain_missing:calibration_schedule/);
  assert.match(result.denialReasons.join('|'), /domain_evidence_missing:calibration_evidence/);
  assert.match(result.denialReasons.join('|'), /equipment_calibration_due_or_invalid:eq-ecg-alpha-001/);
  assert.match(result.denialReasons.join('|'), /calibration_event_traceability_hash_invalid:cal-event-alpha-001/);
  assert.match(result.denialReasons.join('|'), /calibration_event_next_due_mismatch:cal-event-alpha-001/);
});

test('equipment calibration readiness blocks defects quarantine gaps and missing use checks', async () => {
  const { evaluateEquipmentCalibrationReadiness } = await loadEquipmentCalibrationReadiness();

  const result = evaluateEquipmentCalibrationReadiness(
    readinessInput({
      equipmentRecords: [
        equipmentRecord({
          currentCheckRecordRef: 'check-missing',
          defectStatus: 'defective',
          quarantineStatus: 'quarantined',
        }),
      ],
      defectQuarantineRecords: [],
      readinessControls: {
        openDefectCount: 1,
        quarantinedEquipmentCount: 1,
        allCurrentUseBlockedForDefects: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /equipment_check_record_missing:eq-ecg-alpha-001/);
  assert.match(result.denialReasons.join('|'), /equipment_not_fit_for_use:eq-ecg-alpha-001/);
  assert.match(result.denialReasons.join('|'), /equipment_quarantined_without_release:eq-ecg-alpha-001/);
  assert.match(result.denialReasons.join('|'), /equipment_defect_record_missing:eq-ecg-alpha-001/);
  assert.match(result.denialReasons.join('|'), /open_defect_count_present/);
  assert.match(result.denialReasons.join('|'), /quarantined_equipment_count_present/);
  assert.match(result.denialReasons.join('|'), /defective_equipment_use_block_attestation_absent/);
});

test('equipment calibration readiness denies authority human review and HLC defects', async () => {
  const { evaluateEquipmentCalibrationReadiness } = await loadEquipmentCalibrationReadiness();

  const result = evaluateEquipmentCalibrationReadiness(
    readinessInput({
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-beta',
      actor: {
        did: 'did:exo:automation-alpha',
        kind: 'ai_agent',
      },
      authority: {
        permissions: ['read'],
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1803000060000, logical: 0 },
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        decisionForum: {
          verified: false,
          humanGate: { verified: false },
          quorum: { status: 'not_met' },
          openChallenge: true,
        },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /tenant_boundary_violation/);
  assert.match(result.denialReasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(result.denialReasons.join('|'), /human_actor_required/);
  assert.match(result.denialReasons.join('|'), /equipment_calibration_authority_missing/);
  assert.match(result.denialReasons.join('|'), /review_time_not_after_assessment/);
  assert.match(result.denialReasons.join('|'), /decision_forum_unverified/);
  assert.match(result.denialReasons.join('|'), /human_gate_unverified/);
  assert.match(result.denialReasons.join('|'), /quorum_not_met/);
  assert.match(result.denialReasons.join('|'), /challenge_open/);
});

test('equipment calibration readiness rejects raw equipment content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateEquipmentCalibrationReadiness } = await loadEquipmentCalibrationReadiness();

  assert.throws(
    () =>
      evaluateEquipmentCalibrationReadiness({
        ...readinessInput(),
        rawEquipmentRecord: 'raw equipment calibration note for Participant Alice serial number 123',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateEquipmentCalibrationReadiness({
        ...readinessInput(),
        facilitySecret: 'prod-secret',
      }),
    ProtectedContentError,
  );
});
