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

const DIGEST_A = '0a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef';
const DIGEST_B = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_C = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_D = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_E = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_F = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_G = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_H = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_I = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_J = '9999999999999999999999999999999999999999999999999999999999999999';
const DIGEST_K = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_L = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const REQUIRED_VALIDATION_TYPES = [
  'audit_trail',
  'backup_restore',
  'data_integrity',
  'electronic_signature',
  'installation_qualification',
  'integration_boundary',
  'operational_qualification',
  'performance_qualification',
  'security_access',
  'user_acceptance',
];

const REQUIRED_RELIABILITY_SCENARIOS = [
  'duplicate_submission',
  'integration_failure',
  'interrupted_upload',
  'partial_failure',
  'retry_scenario',
];

async function loadElectronicSystemValidation() {
  try {
    return await import('../src/electronic-system-validation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica electronic system validation module must exist and load: ${error.message}`);
  }
}

function validationEvidence(evidenceType, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_G, DIGEST_H, DIGEST_I, DIGEST_J];
  return {
    evidenceRef: `VAL-${evidenceType.toUpperCase()}-001`,
    evidenceType,
    artifactHash: hashes[index],
    verificationHash: hashes[(index + 1) % hashes.length],
    result: 'passed',
    executedByDid: 'did:exo:validation-engineer-alpha',
    reviewedByDid: 'did:exo:quality-reviewer-alpha',
    executedAtHlc: { physicalMs: 1795300001000 + index, logical: 0 },
    reviewedAtHlc: { physicalMs: 1795300002000 + index, logical: 0 },
    metadataOnly: true,
    rawTrialDataExcluded: true,
    protectedPayloadExcluded: true,
  };
}

function reliabilityScenario(scenario, index) {
  return {
    scenario,
    evidenceRef: `REL-${scenario.toUpperCase()}-001`,
    evidenceHash: [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index],
    exercisedAtHlc: { physicalMs: 1795300010000 + index, logical: 0 },
    passed: true,
    failClosedObserved: true,
    reconciliationEvidenceHash: [DIGEST_G, DIGEST_H, DIGEST_I, DIGEST_J, DIGEST_K][index],
  };
}

function electronicSystemInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'system_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['system_validation', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    system: {
      systemRef: 'EDC-SYS-ALPHA',
      systemType: 'edc',
      systemNameHash: DIGEST_B,
      protocolRef: 'protocol-cm-001',
      siteRef: 'site-alpha',
      ownerDid: 'did:exo:system-owner-alpha',
      versionRef: '2026.05.validated',
      intendedUseHash: DIGEST_C,
      configurationHash: DIGEST_D,
      dataFlowHash: DIGEST_E,
      riskAssessmentHash: DIGEST_F,
      accessPolicyHash: DIGEST_G,
      auditTrailPolicyHash: DIGEST_H,
      backupRecoveryHash: DIGEST_I,
      changeControlHash: DIGEST_J,
      vendorQualificationHash: DIGEST_K,
      cybersecurityHash: DIGEST_L,
      dataCollectionUse: true,
      metadataOnly: true,
      sourcePayloadsRemainExternal: true,
      productionTrustClaim: false,
    },
    validationPlan: {
      planRef: 'VAL-PLAN-EDC-SYS-ALPHA',
      planVersion: 'v1',
      approved: true,
      approvedByDid: 'did:exo:quality-director-alpha',
      approvalHash: DIGEST_C,
      approvedAtHlc: { physicalMs: 1795300000000, logical: 0 },
      requiredEvidenceTypes: REQUIRED_VALIDATION_TYPES,
      acceptanceCriteriaHash: DIGEST_D,
      traceabilityMatrixHash: DIGEST_E,
      metadataOnly: true,
    },
    validationEvidence: REQUIRED_VALIDATION_TYPES.map(validationEvidence).reverse(),
    release: {
      releaseRef: 'SYS-RELEASE-EDC-SYS-ALPHA',
      validatedAtHlc: { physicalMs: 1795300018000, logical: 0 },
      releasedAtHlc: { physicalMs: 1795300020000, logical: 0 },
      releaseHash: DIGEST_F,
      releasedByDid: 'did:exo:quality-manager-alpha',
      humanApproved: true,
      openCriticalDefectCount: 0,
      openMajorDefectCount: 0,
      unresolvedDeviationRefs: [],
      trainingCommunicationHash: DIGEST_G,
      goLiveChecklistHash: DIGEST_H,
    },
    reliabilityPlan: {
      planRef: 'REL-PLAN-EDC-SYS-ALPHA',
      status: 'verified',
      planHash: DIGEST_I,
      evaluatedAtHlc: { physicalMs: 1795300016000, logical: 0 },
      partialFailureMode: 'fail_closed',
      integrationFailureMode: 'queue_and_reconcile',
      interruptedUploadMode: 'resume_from_manifest',
      duplicateSubmissionMode: 'idempotent_reject',
      retryMode: 'bounded_idempotent_retry',
      idempotencyKeyRequired: true,
      duplicateSubmissionDetection: true,
      interruptedUploadRecovery: true,
      retryBackoffStrategy: 'bounded_exponential',
      maxRetryCount: 5,
      deadLetterQueueEnabled: true,
      reconciliationRequired: true,
      monitoringEvidenceHash: DIGEST_J,
    },
    reliabilityScenarios: REQUIRED_RELIABILITY_SCENARIOS.map(reliabilityScenario).reverse(),
    integrationReadiness: {
      required: true,
      readinessRef: 'cmgi_ready_edc_alpha',
      status: 'ready',
      readinessHash: DIGEST_K,
      governedApiOnly: true,
      webhookSignatureRequired: true,
      rawPayloadLoggingDisabled: true,
    },
    privacyBoundary: {
      boundaryRef: 'PRIV-SYS-EDC-SYS-ALPHA',
      boundaryHash: DIGEST_L,
      phiPiiExcludedFromReceipts: true,
      sponsorConfidentialMinimized: true,
      payloadsRemainInSourceSystems: true,
      sourceDocumentsExcluded: true,
      disclosureLogRequired: true,
      telemetryRawPayloadDisabled: true,
    },
    auditTrail: {
      policyRef: 'AUDIT-POLICY-EDC-SYS-ALPHA',
      policyHash: DIGEST_A,
      appendOnly: true,
      tamperEvident: true,
      completeEventFamilies: [
        'access',
        'approval',
        'authentication',
        'delegation',
        'decision',
        'document_change',
        'evidence',
        'export',
        'privileged_action',
      ],
      lastVerifiedAtHlc: { physicalMs: 1795300017000, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      scopeHash: DIGEST_B,
      evidenceRefs: ['VAL-DATA_INTEGRITY-001', 'REL-RETRY_SCENARIO-001'],
      limitationHashes: [DIGEST_C],
    },
    custodyDigest: DIGEST_D,
  };
}

test('electronic system validation stores deterministic FR-033 evidence with NFR-012 reliability coverage', async () => {
  const { evaluateElectronicSystemValidation } = await loadElectronicSystemValidation();

  const resultA = evaluateElectronicSystemValidation(electronicSystemInput());
  const resultB = evaluateElectronicSystemValidation({
    ...electronicSystemInput(),
    validationPlan: {
      ...electronicSystemInput().validationPlan,
      requiredEvidenceTypes: [...REQUIRED_VALIDATION_TYPES].reverse(),
    },
    validationEvidence: [...electronicSystemInput().validationEvidence].reverse(),
    reliabilityScenarios: [...electronicSystemInput().reliabilityScenarios].reverse(),
    auditTrail: {
      ...electronicSystemInput().auditTrail,
      completeEventFamilies: [...electronicSystemInput().auditTrail.completeEventFamilies].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.validationRecord.systemValidated, true);
  assert.equal(resultA.validationRecord.reliabilityVerified, true);
  assert.equal(resultA.validationRecord.trialDataCollectionSystem, true);
  assert.equal(resultA.validationRecord.metadataOnly, true);
  assert.equal(resultA.validationRecord.sourcePayloadsStayExternal, true);
  assert.equal(resultA.validationRecord.trustState, 'inactive');
  assert.equal(resultA.validationRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.validationRecord.evidenceTypes, REQUIRED_VALIDATION_TYPES);
  assert.deepEqual(resultA.validationRecord.reliabilityScenarios, REQUIRED_RELIABILITY_SCENARIOS);
  assert.equal(resultA.validationRecord.openDefectCount, 0);
  assert.equal(resultA.validationRecord.validationRecordId, resultB.validationRecord.validationRecordId);
  assert.equal(resultA.validationRecord.validationHash, resultB.validationRecord.validationHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'electronic_system_validation');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|patient|source document|raw trial data|api key/iu);
});

test('electronic system validation fails closed for missing evidence reliability defects and AI authority', async () => {
  const { evaluateElectronicSystemValidation } = await loadElectronicSystemValidation();
  const input = electronicSystemInput();
  input.actor.kind = 'ai_agent';
  input.validationEvidence = input.validationEvidence.filter((item) => item.evidenceType !== 'performance_qualification');
  input.release.openCriticalDefectCount = 1;
  input.reliabilityPlan.status = 'draft';
  input.reliabilityPlan.duplicateSubmissionDetection = false;
  input.reliabilityScenarios = input.reliabilityScenarios.filter((item) => item.scenario !== 'duplicate_submission');
  input.integrationReadiness.status = 'blocked';
  input.auditTrail.completeEventFamilies = ['authentication'];
  input.aiAssistance.finalAuthority = true;

  const result = evaluateElectronicSystemValidation(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.validationRecord.systemValidated, false);
  assert.equal(result.validationRecord.reliabilityVerified, false);
  assert.match(result.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(result.reasons.join('|'), /validation_evidence_missing:performance_qualification/);
  assert.match(result.reasons.join('|'), /release_critical_defects_open/);
  assert.match(result.reasons.join('|'), /reliability_plan_not_verified/);
  assert.match(result.reasons.join('|'), /duplicate_submission_detection_absent/);
  assert.match(result.reasons.join('|'), /reliability_scenario_missing:duplicate_submission/);
  assert.match(result.reasons.join('|'), /integration_readiness_not_ready/);
  assert.match(result.reasons.join('|'), /audit_trail_family_missing:access/);
});

test('electronic system validation enforces HLC ordering and retry boundaries', async () => {
  const { evaluateElectronicSystemValidation } = await loadElectronicSystemValidation();
  const sameTick = electronicSystemInput();
  sameTick.validationEvidence[0].executedAtHlc = { physicalMs: 1795300001000, logical: 0 };
  sameTick.validationEvidence[0].reviewedAtHlc = { physicalMs: 1795300001000, logical: 1 };
  sameTick.reliabilityPlan.evaluatedAtHlc = { physicalMs: 1795300015000, logical: 1 };
  sameTick.release.validatedAtHlc = { physicalMs: 1795300015000, logical: 2 };
  sameTick.release.releasedAtHlc = { physicalMs: 1795300020000, logical: 0 };

  const permitted = evaluateElectronicSystemValidation(sameTick);
  assert.equal(permitted.decision, 'permitted');

  const invalid = electronicSystemInput();
  invalid.validationEvidence[0].reviewedAtHlc = invalid.validationEvidence[0].executedAtHlc;
  invalid.validationEvidence[1].executedAtHlc = { physicalMs: 1795300001001, logical: -1 };
  invalid.release.releasedAtHlc = { physicalMs: 1795300015000, logical: 0 };
  invalid.reliabilityPlan.maxRetryCount = 0;
  invalid.reliabilityPlan.retryBackoffStrategy = 'unbounded';
  invalid.reliabilityScenarios[0].passed = false;

  const denied = evaluateElectronicSystemValidation(invalid);
  assert.equal(denied.decision, 'denied');
  assert.match(denied.reasons.join('|'), /validation_review_not_after_execution/);
  assert.match(denied.reasons.join('|'), /validation_execution_time_invalid/);
  assert.match(denied.reasons.join('|'), /release_before_validation/);
  assert.match(denied.reasons.join('|'), /retry_count_invalid/);
  assert.match(denied.reasons.join('|'), /retry_backoff_strategy_invalid/);
  assert.match(denied.reasons.join('|'), /reliability_scenario_not_passed/);
});

test('electronic system validation supports non-integrated source capture without FR-048 readiness', async () => {
  const { evaluateElectronicSystemValidation } = await loadElectronicSystemValidation();
  const input = electronicSystemInput();
  input.system.systemRef = 'SOURCE-CAPTURE-ALPHA';
  input.system.systemType = 'source_capture';
  input.integrationReadiness = {
    required: false,
    readinessRef: null,
    status: 'not_applicable',
    readinessHash: null,
    governedApiOnly: false,
    webhookSignatureRequired: false,
    rawPayloadLoggingDisabled: true,
  };
  input.aiAssistance = { used: false };

  const result = evaluateElectronicSystemValidation(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.validationRecord.integrationReadinessRequired, false);
  assert.equal(result.validationRecord.integrationReady, true);
  assert.equal(result.validationRecord.aiAssisted, false);
});

test('electronic system validation accepts eISF systems as governed site-file evidence systems', async () => {
  const { evaluateElectronicSystemValidation } = await loadElectronicSystemValidation();
  const input = electronicSystemInput();
  input.system.systemRef = 'EISF-SYS-ALPHA';
  input.system.systemType = 'eisf';
  input.integrationReadiness.readinessRef = 'cmgi_ready_eisf_alpha';

  const result = evaluateElectronicSystemValidation(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.validationRecord.systemType, 'eisf');
  assert.equal(result.validationRecord.systemValidated, true);
  assert.equal(result.validationRecord.integrationReady, true);
  assert.equal(result.validationRecord.sourcePayloadsStayExternal, true);
  assert.equal(result.receipt.anchorPayload.artifactType, 'electronic_system_validation');
  assert.doesNotMatch(JSON.stringify(result), /Participant Alice|raw trial data|source document|api key/iu);
});

test('electronic system validation rejects raw trial data validation content and secrets', async () => {
  const { evaluateElectronicSystemValidation, ProtectedContentError } = await loadElectronicSystemValidation();
  const inertMarkers = electronicSystemInput();
  inertMarkers.validationEvidence[0].rawValidationData = [];
  inertMarkers.validationEvidence[1].rawUploadData = false;
  inertMarkers.integrationReadiness.apiKey = {};

  assert.equal(evaluateElectronicSystemValidation(inertMarkers).decision, 'permitted');

  const input = electronicSystemInput();
  input.validationEvidence[0].rawTrialData = 'patient Alice source document values';

  assert.throws(() => evaluateElectronicSystemValidation(input), ProtectedContentError);

  const secretInput = electronicSystemInput();
  secretInput.integrationReadiness.apiKey = 'cm_live_secret';

  assert.throws(() => evaluateElectronicSystemValidation(secretInput), ProtectedContentError);

  const numericRawInput = electronicSystemInput();
  numericRawInput.validationEvidence[0].rawValidationData = 42;

  assert.throws(() => evaluateElectronicSystemValidation(numericRawInput), ProtectedContentError);
});
