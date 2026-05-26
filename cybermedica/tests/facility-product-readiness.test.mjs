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

async function loadFacilityProductReadiness() {
  try {
    return await import('../src/facility-product-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica facility-product-readiness module must exist and load: ${error.message}`);
  }
}

function facilityReadinessInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:facility-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'manage_facility_readiness'],
      authorityChainHash: DIGEST_F,
    },
    facility: {
      facilityRef: 'FAC-SITE-ALPHA-01',
      locationRef: 'LOC-SITE-ALPHA-MAIN',
      protocolRef: 'protocol-cardiac-alpha',
      readinessStatus: 'ready',
      approvalStatus: 'approved',
      trialSpecificRequirementsHash: DIGEST_A,
      workEnvironmentAssessmentHash: DIGEST_B,
      participantEnvironmentAssessmentHash: DIGEST_C,
      staffWellbeingAssessmentHash: DIGEST_D,
      healthSafetyAssessmentHash: DIGEST_E,
      accessibilityAssessmentHash: DIGEST_A,
      maintenanceProgramHash: DIGEST_B,
      monitoringEvidenceHash: DIGEST_C,
      utilityEvidence: [
        { utility: 'backup_power', status: 'verified', evidenceHash: DIGEST_D },
        { utility: 'temperature_monitoring', status: 'verified', evidenceHash: DIGEST_E },
      ],
      storageEvidence: [{ storage: 'restricted_ip_storage', status: 'verified', evidenceHash: DIGEST_A }],
      securityEvidence: [{ control: 'restricted_area_access', status: 'verified', evidenceHash: DIGEST_B }],
      privacyEvidence: [{ control: 'participant_privacy_zone', status: 'verified', evidenceHash: DIGEST_C }],
      infrastructure: [
        { infrastructureRef: 'INF-FREEZER-POWER-01', status: 'qualified', evidenceHash: DIGEST_D },
        { infrastructureRef: 'INF-PRIVATE-ROOM-01', status: 'qualified', evidenceHash: DIGEST_E },
      ],
      gapList: [],
    },
    equipment: [
      {
        equipmentRef: 'EQ-ECG-ALPHA-01',
        equipmentType: 'ecg',
        manufacturerRef: 'mfg-ecg-alpha',
        serialNumberHash: DIGEST_A,
        locationRef: 'LOC-SITE-ALPHA-MAIN',
        protocolRef: 'protocol-cardiac-alpha',
        calibrationRequired: true,
        calibrationFrequencyDays: 90,
        calibrationResponsibleDid: 'did:exo:biomed-alpha',
        calibrationStandardTraceabilityHash: DIGEST_B,
        lastCalibrationAtHlc: { physicalMs: 1790000000000, logical: 0 },
        nextCalibrationDueHlc: { physicalMs: 1797000000000, logical: 0 },
        calibrationEvidenceHash: DIGEST_C,
        checkBeforeUseRequired: true,
        checkBeforeUseEvidenceHash: DIGEST_D,
        defectStatus: 'fit_for_use',
        quarantineStatus: 'not_quarantined',
        returnToServiceApproval: null,
        maintenanceRecordHash: DIGEST_E,
      },
      {
        equipmentRef: 'EQ-SCALE-ALPHA-01',
        equipmentType: 'scale',
        manufacturerRef: 'mfg-scale-alpha',
        serialNumberHash: DIGEST_B,
        locationRef: 'LOC-SITE-ALPHA-MAIN',
        protocolRef: 'protocol-cardiac-alpha',
        calibrationRequired: false,
        calibrationFrequencyDays: 0,
        calibrationResponsibleDid: 'did:exo:facility-manager-alpha',
        calibrationStandardTraceabilityHash: DIGEST_C,
        lastCalibrationAtHlc: null,
        nextCalibrationDueHlc: null,
        calibrationEvidenceHash: null,
        checkBeforeUseRequired: false,
        checkBeforeUseEvidenceHash: null,
        defectStatus: 'fit_for_use',
        quarantineStatus: 'not_quarantined',
        returnToServiceApproval: null,
        maintenanceRecordHash: DIGEST_D,
      },
    ],
    products: [
      {
        productRef: 'IP-CARDIAC-ALPHA-0001',
        protocolRef: 'protocol-cardiac-alpha',
        sponsorRef: 'sponsor-alpha',
        productType: 'investigational_product',
        batchSerialHash: DIGEST_A,
        expiresAtHlc: { physicalMs: 1810000000000, logical: 0 },
        quantityReceived: 120,
        quantityDispensed: 24,
        quantityReturned: 0,
        quantityDisposed: 0,
        currentStock: 96,
        receiptRecordHash: DIGEST_B,
        storageRequirementHash: DIGEST_C,
        storageLocationRef: 'PHARMACY-RESTRICTED-01',
        temperatureControlEvidenceHash: DIGEST_D,
        accessPermissionRefs: ['ip_manager', 'principal_investigator'],
        dispensingResponsibleDid: 'did:exo:ip-manager-alpha',
        blindingResponsibleDid: 'did:exo:unblinded-pharmacist-alpha',
        transportRequirementHash: DIGEST_E,
        transitIntegrityControlHash: DIGEST_F,
        uniqueCodeNumberLinkageHash: DIGEST_A,
        administrationRecordHash: DIGEST_B,
        stockReconciliationHash: DIGEST_C,
        expiredProductManagementHash: DIGEST_D,
        damagedContaminatedManagementHash: DIGEST_E,
        returnDisposalRecordHash: DIGEST_F,
        nonconformityRef: null,
      },
    ],
    launchReadiness: {
      facilityReadinessRequired: true,
      equipmentReadinessRequired: true,
      productHandlingReadinessRequired: true,
      authorizedLaunchCheckRef: 'procedure-6-launch-check-001',
      readinessAssessedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-facility-product-readiness-001',
        workflowReceiptId: 'df-workflow-facility-product-readiness-001',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      qualityReviewerDid: 'did:exo:quality-manager-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      facilityManagerDid: 'did:exo:facility-manager-alpha',
      productManagerDid: 'did:exo:ip-manager-alpha',
    },
    custodyDigest: DIGEST_E,
  };
}

test('facility equipment and product readiness creates deterministic inactive launch metadata receipts', async () => {
  const { evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  const recordA = evaluateFacilityProductReadiness(facilityReadinessInput());
  const recordB = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    facility: {
      ...facilityReadinessInput().facility,
      infrastructure: [...facilityReadinessInput().facility.infrastructure].reverse(),
      utilityEvidence: [...facilityReadinessInput().facility.utilityEvidence].reverse(),
      securityEvidence: [...facilityReadinessInput().facility.securityEvidence].reverse(),
    },
    equipment: [...facilityReadinessInput().equipment].reverse(),
    products: [...facilityReadinessInput().products].reverse(),
  });

  assert.equal(recordA.decision, 'permitted');
  assert.equal(recordA.failClosed, false);
  assert.equal(recordA.readiness.readinessStatus, 'ready_for_launch');
  assert.equal(recordA.readiness.facilityStatus, 'ready');
  assert.equal(recordA.readiness.equipmentStatus, 'ready');
  assert.equal(recordA.readiness.productStatus, 'ready');
  assert.equal(recordA.readiness.openGapCount, 0);
  assert.equal(recordA.readiness.equipmentCount, 2);
  assert.equal(recordA.readiness.productCount, 1);
  assert.equal(recordA.readiness.aiFinalAuthority, false);
  assert.equal(recordA.readiness.exochainProductionClaim, false);
  assert.deepEqual(recordA.readiness.requiredLaunchChecks, [
    'equipment_readiness',
    'facility_readiness',
    'product_handling_readiness',
  ]);
  assert.equal(recordA.readiness.readinessId, recordB.readiness.readinessId);
  assert.equal(recordA.receipt.receiptId, recordB.receipt.receiptId);
  assert.equal(recordA.receipt.actionHash, recordB.receipt.actionHash);
  assert.equal(recordA.receipt.trustState, 'inactive');
  assert.equal(recordA.receipt.anchorPayload.artifactType, 'facility_equipment_product_readiness');
  assert.doesNotMatch(JSON.stringify(recordA), /Participant Alice|source document|raw product|serial number 123/iu);
});

test('defective or quarantined equipment blocks launch readiness until return to service is approved', async () => {
  const { evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  const result = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    equipment: [
      {
        ...facilityReadinessInput().equipment[0],
        defectStatus: 'defective',
        quarantineStatus: 'quarantined',
        returnToServiceApproval: {
          approved: false,
          approvedByDid: '',
          approvalEvidenceHash: DIGEST_A,
        },
      },
    ],
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.readiness.readinessStatus, 'not_ready');
  assert.equal(result.readiness.equipmentStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /equipment_not_fit_for_use/);
  assert.match(result.denialReasons.join('|'), /equipment_quarantined_without_return_to_service/);
});

test('product accountability denies expired stock and broken reconciliation', async () => {
  const { evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  const result = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    products: [
      {
        ...facilityReadinessInput().products[0],
        expiresAtHlc: { physicalMs: 1780000000000, logical: 0 },
        quantityDispensed: 25,
        currentStock: 96,
        nonconformityRef: '',
      },
    ],
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.readiness.productStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /product_expired_or_expiration_time_invalid/);
  assert.match(result.denialReasons.join('|'), /product_stock_reconciliation_mismatch/);
  assert.match(result.denialReasons.join('|'), /product_nonconformity_linkage_absent/);
});

test('facility readiness denies gaps missing mitigation and human launch governance', async () => {
  const { evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  const result = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    facility: {
      ...facilityReadinessInput().facility,
      approvalStatus: 'pending',
      gapList: [
        {
          gapRef: 'FAC-GAP-001',
          severity: 'major',
          mitigationEvidenceHash: '',
          ownerDid: 'did:exo:facility-manager-alpha',
          targetCloseHlc: { physicalMs: 1795000000000, logical: 0 },
        },
      ],
    },
    review: {
      ...facilityReadinessInput().review,
      decisionForum: {
        ...facilityReadinessInput().review.decisionForum,
        humanGate: { verified: false },
      },
      principalInvestigatorDid: '',
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.readiness.facilityStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /facility_not_approved/);
  assert.match(result.denialReasons.join('|'), /facility_gap_mitigation_absent/);
  assert.match(result.denialReasons.join('|'), /human_gate_unverified/);
  assert.match(result.denialReasons.join('|'), /principal_investigator_absent/);
});

test('HLC ordering blocks invalid assessment and stale calibration windows', async () => {
  const { evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  const invalidAssessment = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    launchReadiness: {
      ...facilityReadinessInput().launchReadiness,
      readinessAssessedAtHlc: { physicalMs: 1795000000000, logical: -1 },
    },
  });

  assert.equal(invalidAssessment.decision, 'denied');
  assert.match(invalidAssessment.denialReasons.join('|'), /launch_readiness_assessment_time_invalid/);

  const staleCalibration = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    launchReadiness: {
      ...facilityReadinessInput().launchReadiness,
      readinessAssessedAtHlc: { physicalMs: 1797000000000, logical: 0 },
    },
    equipment: [
      {
        ...facilityReadinessInput().equipment[0],
        lastCalibrationAtHlc: { physicalMs: 1797000000000, logical: 2 },
        nextCalibrationDueHlc: { physicalMs: 1797000000000, logical: 1 },
      },
    ],
    products: [
      {
        ...facilityReadinessInput().products[0],
        expiresAtHlc: { physicalMs: 1810000000000, logical: 2 },
      },
    ],
  });

  assert.equal(staleCalibration.decision, 'denied');
  assert.match(staleCalibration.denialReasons.join('|'), /equipment_calibration_window_invalid/);

  const logicalReady = evaluateFacilityProductReadiness({
    ...facilityReadinessInput(),
    launchReadiness: {
      ...facilityReadinessInput().launchReadiness,
      readinessAssessedAtHlc: { physicalMs: 1797000000000, logical: 1 },
    },
    equipment: [
      {
        ...facilityReadinessInput().equipment[0],
        lastCalibrationAtHlc: { physicalMs: 1797000000000, logical: 2 },
        nextCalibrationDueHlc: { physicalMs: 1797000000000, logical: 2 },
      },
    ],
    products: [
      {
        ...facilityReadinessInput().products[0],
        expiresAtHlc: { physicalMs: 1810000000000, logical: 2 },
      },
    ],
  });

  assert.equal(logicalReady.decision, 'permitted');
});

test('raw facility equipment or product content is rejected before receipts are created', async () => {
  const { ProtectedContentError, evaluateFacilityProductReadiness } = await loadFacilityProductReadiness();

  assert.throws(
    () =>
      evaluateFacilityProductReadiness({
        ...facilityReadinessInput(),
        productAccountabilityNarrative: 'raw product accountability source document body',
      }),
    ProtectedContentError,
  );
});
