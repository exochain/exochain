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

async function loadEmergencyActions() {
  try {
    return await import('../src/emergency-actions.mjs');
  } catch (error) {
    assert.fail(`CyberMedica emergency action module must exist and load: ${error.message}`);
  }
}

function emergencyActionInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'emergency_action'],
      authorityChainHash: DIGEST_A,
    },
    emergencyAction: {
      actionRef: 'EA-PARTICIPANT-SAFETY-0001',
      studyRef: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      participantCodeHash: DIGEST_B,
      participantCodeScope: 'site_subject_code',
      actionType: 'participant_safety',
      triggerDomain: 'participant_safety',
      severity: 'critical',
      priorApprovalImpracticable: true,
      harmPreventionRequired: true,
      actionStartedAtHlc: { physicalMs: 1793000000000, logical: 0 },
      actionCompletedAtHlc: { physicalMs: 1793000300000, logical: 0 },
      recordedAtHlc: { physicalMs: 1793000600000, logical: 0 },
      actionEvidenceHash: DIGEST_C,
      justificationHash: DIGEST_D,
      noPriorApprovalRationaleHash: DIGEST_E,
      scopeHash: DIGEST_F,
      policyRefs: ['participant-safety-escalation-v1', 'emergency-action-rule-9-v1'],
      status: 'review_pending',
    },
    clinicalOversight: {
      responsibleClinicianDid: 'did:exo:principal-investigator-alpha',
      siteQualityLeadDid: 'did:exo:site-quality-manager-alpha',
      safetyAssessmentHash: DIGEST_A,
      participantSafetyProtected: true,
    },
    reporting: {
      sponsor: {
        required: true,
        timelineRef: 'sponsor-emergency-action-same-day',
        dueAtHlc: { physicalMs: 1793003600000, logical: 0 },
        status: 'submitted',
        submittedAtHlc: { physicalMs: 1793003000000, logical: 0 },
        evidenceHash: DIGEST_B,
      },
      irbIec: {
        required: true,
        timelineRef: 'irb-emergency-action-24h',
        dueAtHlc: { physicalMs: 1793086400000, logical: 0 },
        status: 'submitted',
        submittedAtHlc: { physicalMs: 1793007200000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
      regulatory: {
        required: false,
        status: 'not_required',
        rationaleHash: DIGEST_D,
      },
    },
    notifications: [
      {
        party: 'principal_investigator',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1793000900000, logical: 0 },
        evidenceHash: DIGEST_A,
      },
      {
        party: 'site_quality_lead',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1793001200000, logical: 0 },
        evidenceHash: DIGEST_B,
      },
      {
        party: 'sponsor_safety_contact',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1793001500000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
    ],
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      promptHash: DIGEST_D,
      outputHash: DIGEST_E,
      evidenceUsedHashes: [DIGEST_A, DIGEST_C],
      recommendedHumanReviewerRole: 'decision_forum_chair',
    },
    retrospectiveReview: {
      required: true,
      status: 'pending',
      dueAtHlc: { physicalMs: 1793168400000, logical: 0 },
      evidenceBundleHash: DIGEST_F,
    },
    custodyDigest: DIGEST_F,
  };
}

function reviewedEmergencyActionInput() {
  return {
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      status: 'retrospective_reviewed',
    },
    retrospectiveReview: {
      required: true,
      status: 'complete',
      dueAtHlc: { physicalMs: 1793168400000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1793090000000, logical: 0 },
      reviewerDid: 'did:exo:decision-forum-chair-alpha',
      outcome: 'ratify_with_conditions',
      rationaleHash: DIGEST_A,
      evidenceBundleHash: DIGEST_F,
      conditionHashes: [DIGEST_D],
      followUpActions: [
        {
          actionRef: 'EA-FOLLOWUP-0001',
          ownerDid: 'did:exo:site-quality-manager-alpha',
          dueAtHlc: { physicalMs: 1793600000000, logical: 0 },
          evidenceHash: DIGEST_E,
        },
      ],
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-emergency-action-review-0001',
        workflowReceiptId: 'df-workflow-emergency-action-review-0001',
      },
    },
  };
}

test('emergency action records create deterministic inactive review-required receipts', async () => {
  const { evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  const resultA = evaluateEmergencyActionWorkflow(emergencyActionInput());
  const resultB = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      policyRefs: [...emergencyActionInput().emergencyAction.policyRefs].reverse(),
    },
    aiAssistance: {
      ...emergencyActionInput().aiAssistance,
      evidenceUsedHashes: [...emergencyActionInput().aiAssistance.evidenceUsedHashes].reverse(),
    },
    notifications: [...emergencyActionInput().notifications].reverse(),
    reporting: {
      regulatory: emergencyActionInput().reporting.regulatory,
      sponsor: emergencyActionInput().reporting.sponsor,
      irbIec: emergencyActionInput().reporting.irbIec,
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.emergencyAction.actionType, 'participant_safety');
  assert.equal(resultA.emergencyAction.reviewRequired, true);
  assert.equal(resultA.emergencyAction.retrospectiveReviewStatus, 'required_pending');
  assert.equal(resultA.emergencyAction.reportingStatus, 'complete');
  assert.equal(resultA.emergencyAction.notificationStatus, 'complete');
  assert.equal(resultA.emergencyAction.aiFinalAuthority, false);
  assert.equal(resultA.emergencyAction.exochainProductionClaim, false);
  assert.deepEqual(resultA.emergencyAction.requiredEscalationRoles, [
    'decision_forum',
    'principal_investigator',
    'site_quality_lead',
    'sponsor_safety_contact',
  ]);
  assert.equal(resultA.emergencyAction.emergencyActionId, resultB.emergencyAction.emergencyActionId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'emergency_action_record');
  assert.equal(resultA.reviewReceipt, null);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|medical record|source document|raw action/iu);
});

test('retrospective review closes only with human Decision Forum governance', async () => {
  const { evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  const result = evaluateEmergencyActionWorkflow(reviewedEmergencyActionInput());

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.emergencyAction.retrospectiveReviewStatus, 'complete');
  assert.equal(result.emergencyAction.reviewOutcome, 'ratify_with_conditions');
  assert.equal(result.emergencyAction.followUpActionCount, 1);
  assert.deepEqual(result.emergencyAction.conditionHashes, [DIGEST_D]);
  assert.equal(result.reviewReceipt.anchorPayload.artifactType, 'emergency_action_retrospective_review');
  assert.equal(result.reviewReceipt.trustState, 'inactive');

  const denied = evaluateEmergencyActionWorkflow({
    ...reviewedEmergencyActionInput(),
    retrospectiveReview: {
      ...reviewedEmergencyActionInput().retrospectiveReview,
      decisionForum: {
        ...reviewedEmergencyActionInput().retrospectiveReview.decisionForum,
        humanGate: { verified: false },
      },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.deepEqual(denied.reasons, ['retrospective_review_governance_absent']);
  assert.equal(denied.reviewReceipt, null);
});

test('emergency action workflow fails closed for unsafe evidence and reporting gaps', async () => {
  const { evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  const result = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    actor: { did: 'did:exo:triage-ai', kind: 'ai_agent' },
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      priorApprovalImpracticable: false,
      justificationHash: DIGEST_A.slice(0, 63),
    },
    reporting: {
      ...emergencyActionInput().reporting,
      sponsor: {
        ...emergencyActionInput().reporting.sponsor,
        status: 'pending',
        evidenceHash: null,
      },
    },
    notifications: emergencyActionInput().notifications.filter((notification) => notification.party !== 'site_quality_lead'),
    retrospectiveReview: {
      ...emergencyActionInput().retrospectiveReview,
      dueAtHlc: { physicalMs: 1793000100000, logical: 0 },
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.deepEqual(result.reasons, [
    'ai_final_authority_forbidden',
    'emergency_justification_hash_invalid',
    'human_actor_required',
    'prior_approval_impracticable_required',
    'retrospective_review_due_before_record',
    'site_quality_lead_notification_incomplete',
    'sponsor_reporting_incomplete',
  ]);
});

test('emergency action workflow validates HLC ordering and same-tick logical order', async () => {
  const { evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  const sameTick = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      actionStartedAtHlc: { physicalMs: 1793000000000, logical: 0 },
      actionCompletedAtHlc: { physicalMs: 1793000000000, logical: 1 },
      recordedAtHlc: { physicalMs: 1793000000000, logical: 2 },
    },
  });
  assert.equal(sameTick.decision, 'permitted');

  const denied = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      actionCompletedAtHlc: { physicalMs: 1792999999999, logical: 0 },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.deepEqual(denied.reasons, ['action_completion_before_start']);
});

test('emergency action workflow reports malformed HLC optional AI and product-handling branches', async () => {
  const { evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  const productHandling = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    aiAssistance: { used: false },
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      actionType: 'product_handling',
      triggerDomain: 'product_handling',
      severity: 'urgent',
      actionStartedAtHlc: { physicalMs: 1793000000000, logical: 0 },
      actionCompletedAtHlc: { physicalMs: 1793000000000, logical: 0 },
      recordedAtHlc: { physicalMs: 1793000000000, logical: 0 },
    },
  });

  assert.equal(productHandling.decision, 'permitted');
  assert.equal(productHandling.emergencyAction.aiAssistanceStatus, 'not_used');
  assert.deepEqual(productHandling.emergencyAction.requiredEscalationRoles, [
    'decision_forum',
    'principal_investigator',
    'site_quality_lead',
    'sponsor_safety_contact',
  ]);

  const malformed = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      actionStartedAtHlc: { physicalMs: 1793000000000, logical: -1 },
      actionCompletedAtHlc: { physicalMs: 1793000000000, logical: 0 },
    },
    reporting: {
      ...emergencyActionInput().reporting,
      regulatory: { status: 'pending' },
    },
  });

  assert.equal(malformed.decision, 'denied');
  assert.match(malformed.reasons.join('|'), /action_start_time_invalid/);
  assert.match(malformed.reasons.join('|'), /action_completion_before_start/);
  assert.match(malformed.reasons.join('|'), /regulatory_reporting_incomplete/);

  const logicalRegression = evaluateEmergencyActionWorkflow({
    ...emergencyActionInput(),
    emergencyAction: {
      ...emergencyActionInput().emergencyAction,
      actionStartedAtHlc: { physicalMs: 1793000000000, logical: 1 },
      actionCompletedAtHlc: { physicalMs: 1793000000000, logical: 0 },
    },
  });

  assert.equal(logicalRegression.decision, 'denied');
  assert.deepEqual(logicalRegression.reasons, ['action_completion_before_start']);
});

test('emergency action workflow rejects raw emergency and participant content before receipts', async () => {
  const { ProtectedContentError, evaluateEmergencyActionWorkflow } = await loadEmergencyActions();

  assert.throws(
    () =>
      evaluateEmergencyActionWorkflow({
        ...emergencyActionInput(),
        emergencyAction: {
          ...emergencyActionInput().emergencyAction,
          rawActionNarrative: 'Participant Alice was stabilized from medical record MRN: A-123',
        },
      }),
    ProtectedContentError,
  );
});
