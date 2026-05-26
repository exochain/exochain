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

async function loadStaffTrainingGapManagement() {
  try {
    return await import('../src/staff-training-gap-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica staff-training-gap-management module must exist and load: ${error.message}`);
  }
}

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const CUSTODY_DIGEST = 'abababababababababababababababababababababababababababababababab';
const AUTHORITY_HASH = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function baseInput() {
  return {
    requestId: 'staff-training-gap-management-alpha',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    protocolId: 'protocol-cardiac-alpha',
    checkedAtHlc: { physicalMs: 1790600000000, logical: 8 },
    actor: { did: 'did:exo:training-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_training_gap', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    trainingMatrix: {
      matrixId: 'training-matrix-protocol-cardiac-alpha',
      status: 'approved',
      verified: true,
      receiptId: 'training-matrix-receipt-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    gap: {
      gapId: 'gap-consent-sop-crc-alpha',
      requirementId: 'req-consent-sop',
      gapReason: 'training_requirement_version_stale',
      actorDid: 'did:exo:crc-alpha',
      role: 'clinical_research_coordinator',
      controlledAction: 'informed_consent_documentation',
      status: 'closed',
      openedAtHlc: { physicalMs: 1790000000000, logical: 1 },
      closedAtHlc: { physicalMs: 1790500000000, logical: 2 },
      evidenceHash: DIGEST_A,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    notification: {
      notifiedAtHlc: { physicalMs: 1790100000000, logical: 0 },
      staffNotified: true,
      supervisorNotified: true,
      notificationEvidenceHash: DIGEST_B,
      metadataOnly: true,
    },
    assignment: {
      assignedAtHlc: { physicalMs: 1790200000000, logical: 0 },
      assignedTrainingRef: 'training-consent-sop-v2',
      dueAtHlc: { physicalMs: 1790400000000, logical: 0 },
      assignmentEvidenceHash: DIGEST_C,
      trainerDid: 'did:exo:trainer-alpha',
      supervisorDid: 'did:exo:supervisor-alpha',
    },
    completion: {
      completedAtHlc: { physicalMs: 1790300000000, logical: 0 },
      trainingRecordRef: 'training-record-consent-sop-crc-alpha',
      trainingRecordHash: DIGEST_D,
      completedVersion: 2,
      requiredVersion: 2,
      evidenceType: 'sop_training_attestation',
      status: 'completed',
    },
    assessment: {
      required: true,
      status: 'passed',
      assessedAtHlc: { physicalMs: 1790350000000, logical: 0 },
      assessmentEvidenceHash: DIGEST_E,
      assessorDid: 'did:exo:supervisor-alpha',
      verifiedByHuman: true,
    },
    competenceVerification: {
      verified: true,
      verifiedAtHlc: { physicalMs: 1790450000000, logical: 0 },
      verifiedByDid: 'did:exo:supervisor-alpha',
      competencyEvidenceHash: DIGEST_F,
      humanGate: { verified: true },
    },
    trainingRecordUpdate: {
      updatedAtHlc: { physicalMs: 1790470000000, logical: 0 },
      updatedRecordHash: DIGEST_1,
      previousRecordHash: DIGEST_2,
      supersedesGap: true,
      metadataOnly: true,
    },
    delegationEligibilityUpdate: {
      updatedAtHlc: { physicalMs: 1790500000000, logical: 1 },
      eligibilityReceiptId: 'cmtd_eligibility_after_gap_alpha',
      eligibilityHash: DIGEST_C,
      controlledActionPermitted: true,
      delegationRef: 'delegation-protocol-cardiac-alpha-crc',
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'training_gap_closed',
      decisionHash: DIGEST_D,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1790520000000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_E,
      reviewedByHuman: true,
    },
    custodyDigest: CUSTODY_DIGEST,
  };
}

test('staff training gap management closes Procedure 13 gaps with deterministic inactive receipts', async () => {
  const { evaluateStaffTrainingGapManagement } = await loadStaffTrainingGapManagement();
  const input = baseInput();

  const closedA = evaluateStaffTrainingGapManagement(input);
  const closedB = evaluateStaffTrainingGapManagement({
    ...input,
    authority: {
      ...input.authority,
      permissions: [...input.authority.permissions].reverse(),
    },
  });

  assert.equal(closedA.decision, 'permitted');
  assert.equal(closedA.failClosed, false);
  assert.deepEqual(closedA.reasons, []);
  assert.equal(closedA.trustState, 'inactive');
  assert.equal(closedA.exochainProductionClaim, false);
  assert.equal(closedA.trainingGap.gapLifecycleHash, closedB.trainingGap.gapLifecycleHash);
  assert.equal(closedA.receipt.receiptId, closedB.receipt.receiptId);
  assert.equal(closedA.receipt.anchorPayload.artifactType, 'staff_training_gap_management');
  assert.equal(closedA.receipt.trustState, 'inactive');
  assert.equal(closedA.trainingGap.status, 'closed');
  assert.deepEqual(closedA.trainingGap.procedureSteps, [
    'gap_created',
    'staff_and_supervisor_notified',
    'training_assigned',
    'training_completed',
    'assessment_completed',
    'competence_verified',
    'training_record_updated',
    'gap_closed',
    'delegation_eligibility_updated',
  ]);
  assert.deepEqual(Object.keys(closedA.trainingGap), [
    'schema',
    'gapManagementId',
    'gapLifecycleHash',
    'tenantId',
    'siteId',
    'protocolId',
    'gapId',
    'requirementId',
    'actorDid',
    'role',
    'controlledAction',
    'status',
    'checkedAtHlc',
    'procedureSteps',
    'evidenceHashes',
    'authorityChainHash',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(closedA), /root-backed production authority/i);
});

test('staff training gap management fails closed for incomplete lifecycle and AI final authority', async () => {
  const { evaluateStaffTrainingGapManagement } = await loadStaffTrainingGapManagement();
  const input = clone(baseInput());

  const denied = evaluateStaffTrainingGapManagement({
    ...input,
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:training-ai-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: AUTHORITY_HASH,
    },
    trainingMatrix: {
      ...input.trainingMatrix,
      status: 'draft',
      verified: false,
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    gap: {
      ...input.gap,
      status: 'open',
      closedAtHlc: null,
      metadataOnly: false,
      protectedContentExcluded: false,
    },
    notification: {
      ...input.notification,
      staffNotified: false,
      supervisorNotified: false,
      notificationEvidenceHash: '',
    },
    assignment: {
      ...input.assignment,
      assignedAtHlc: { physicalMs: 1789999999999, logical: 0 },
      dueAtHlc: { physicalMs: 1789999999998, logical: 0 },
      assignmentEvidenceHash: '',
    },
    completion: {
      ...input.completion,
      status: 'in_progress',
      completedVersion: 1,
      trainingRecordHash: '',
    },
    assessment: {
      ...input.assessment,
      status: 'failed',
      verifiedByHuman: false,
      assessmentEvidenceHash: '',
    },
    competenceVerification: {
      ...input.competenceVerification,
      verified: false,
      humanGate: { verified: false },
      competencyEvidenceHash: '',
    },
    trainingRecordUpdate: {
      ...input.trainingRecordUpdate,
      supersedesGap: false,
      updatedRecordHash: '',
      metadataOnly: false,
    },
    delegationEligibilityUpdate: {
      ...input.delegationEligibilityUpdate,
      controlledActionPermitted: false,
      eligibilityHash: '',
      metadataOnly: false,
    },
    humanReview: {
      ...input.humanReview,
      finalAuthority: 'ai',
      aiFinalAuthority: true,
      reviewedAtHlc: { physicalMs: 1790010000000, logical: 0 },
      metadataOnly: false,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.trainingGap, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('training_gap_authority_missing'));
  assert.ok(denied.reasons.includes('training_matrix_not_approved'));
  assert.ok(denied.reasons.includes('training_matrix_human_gate_unverified'));
  assert.ok(denied.reasons.includes('training_gap_not_closed'));
  assert.ok(denied.reasons.includes('staff_notification_missing'));
  assert.ok(denied.reasons.includes('supervisor_notification_missing'));
  assert.ok(denied.reasons.includes('training_assignment_before_gap_opened'));
  assert.ok(denied.reasons.includes('training_due_before_assignment'));
  assert.ok(denied.reasons.includes('training_completion_not_completed'));
  assert.ok(denied.reasons.includes('training_version_stale'));
  assert.ok(denied.reasons.includes('assessment_not_passed'));
  assert.ok(denied.reasons.includes('assessment_human_verification_absent'));
  assert.ok(denied.reasons.includes('competence_verification_absent'));
  assert.ok(denied.reasons.includes('competence_human_gate_unverified'));
  assert.ok(denied.reasons.includes('training_record_update_not_gap_superseding'));
  assert.ok(denied.reasons.includes('delegation_eligibility_not_permitted'));
  assert.ok(denied.reasons.includes('human_review_final_authority_invalid'));
});

test('staff training gap management rejects protected raw training content and secrets', async () => {
  const { ProtectedContentError, evaluateStaffTrainingGapManagement } = await loadStaffTrainingGapManagement();
  const input = baseInput();

  assert.throws(
    () => evaluateStaffTrainingGapManagement({
      ...input,
      gap: {
        ...input.gap,
        rawTrainingNarrative: 'Participant Jane Smith had a protocol training exception.',
      },
    }),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateStaffTrainingGapManagement({
      ...input,
      assignment: {
        ...input.assignment,
        apiKey: 'secret-key-material',
      },
    }),
    ProtectedContentError,
  );
});

test('staff training gap management handles absent objects as fail-closed denial states', async () => {
  const { evaluateStaffTrainingGapManagement } = await loadStaffTrainingGapManagement();

  const denied = evaluateStaffTrainingGapManagement(null);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('training_gap_absent'));
  assert.ok(denied.reasons.includes('training_matrix_not_approved'));
  assert.equal(denied.trainingGap, null);
  assert.equal(denied.receipt, null);
});
