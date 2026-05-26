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

async function loadSafetyEvents() {
  try {
    return await import('../src/safety-events.mjs');
  } catch (error) {
    assert.fail(`CyberMedica safety-events module must exist and load: ${error.message}`);
  }
}

function susarInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:safety-coordinator-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'manage_safety_events'],
      authorityChainHash: DIGEST_F,
    },
    safetyEvent: {
      eventRef: 'SAFETY-EVENT-2026-0004',
      studyRef: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      participantCodeHash: DIGEST_A,
      participantCodeScope: 'site_subject_code',
      classification: 'susar',
      serious: true,
      expectedness: 'unexpected',
      relatedness: 'probable',
      severity: 'life_threatening',
      onsetAtHlc: { physicalMs: 1790000000000, logical: 0 },
      resolutionAtHlc: { physicalMs: 1790007200000, logical: 0 },
      eventDetailsHash: DIGEST_B,
      investigatorAssessmentHash: DIGEST_C,
      reportEvidenceHashes: [DIGEST_E, DIGEST_D],
      policyRefs: ['ae-sae-susar-reporting-policy-v1', 'participant-safety-escalation-v1'],
      status: 'follow_up_open',
    },
    clinicalResponse: {
      required: true,
      status: 'completed',
      responseEvidenceHash: DIGEST_D,
      initiatedAtHlc: { physicalMs: 1790000001000, logical: 0 },
      completedAtHlc: { physicalMs: 1790000001000, logical: 1 },
      responsibleClinicianDid: 'did:exo:principal-investigator-alpha',
    },
    reporting: {
      sponsor: {
        required: true,
        timelineRef: 'sponsor-sae-susar-expedited',
        dueAtHlc: { physicalMs: 1790003600000, logical: 0 },
        status: 'submitted',
        submittedAtHlc: { physicalMs: 1790003600000, logical: 0 },
        evidenceHash: DIGEST_B,
      },
      irb: {
        required: true,
        timelineRef: 'irb-unexpected-serious-report',
        dueAtHlc: { physicalMs: 1790172800000, logical: 0 },
        status: 'submitted',
        submittedAtHlc: { physicalMs: 1790005400000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
      regulatory: {
        required: true,
        timelineRef: 'regulatory-susar-expedited',
        dueAtHlc: { physicalMs: 1790172800000, logical: 1 },
        status: 'submitted',
        submittedAtHlc: { physicalMs: 1790005400000, logical: 1 },
        evidenceHash: DIGEST_D,
      },
    },
    notifications: [
      {
        party: 'principal_investigator',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1790000300000, logical: 0 },
        evidenceHash: DIGEST_B,
      },
      {
        party: 'sponsor_safety_contact',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1790000400000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
      {
        party: 'site_quality_lead',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1790000500000, logical: 0 },
        evidenceHash: DIGEST_D,
      },
    ],
    investigation: {
      required: true,
      status: 'open',
      investigatorDid: 'did:exo:principal-investigator-alpha',
      planHash: DIGEST_E,
      openedAtHlc: { physicalMs: 1790006000000, logical: 0 },
    },
    followUp: {
      required: true,
      status: 'pending',
      requiredReportCount: 2,
      completedReportCount: 1,
      reportHashes: [DIGEST_C],
      nextDueAtHlc: { physicalMs: 1790604800000, logical: 0 },
    },
    deviationLinkage: {
      required: true,
      deviationRef: 'DEV-2026-0009',
      receiptId: 'cmr-deviation-intake-0009',
    },
    capaLinkage: {
      required: true,
      capaRef: 'CAPA-2026-0017',
      receiptId: 'cmr-capa-intake-0017',
    },
    decisionForum: {
      linkageRequired: true,
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-safety-escalation-0004',
      workflowReceiptId: 'df-workflow-receipt-safety-0004',
    },
    custodyDigest: DIGEST_F,
  };
}

test('SAE SUSAR workflow creates deterministic inactive metadata receipts and escalation routing', async () => {
  const { evaluateSafetyEventWorkflow } = await loadSafetyEvents();

  const recordA = evaluateSafetyEventWorkflow(susarInput());
  const recordB = evaluateSafetyEventWorkflow({
    ...susarInput(),
    notifications: [...susarInput().notifications].reverse(),
    safetyEvent: {
      ...susarInput().safetyEvent,
      policyRefs: [...susarInput().safetyEvent.policyRefs].reverse(),
      reportEvidenceHashes: [...susarInput().safetyEvent.reportEvidenceHashes].reverse(),
    },
    reporting: {
      regulatory: susarInput().reporting.regulatory,
      sponsor: susarInput().reporting.sponsor,
      irb: susarInput().reporting.irb,
    },
  });

  assert.equal(recordA.decision, 'permitted');
  assert.equal(recordA.failClosed, false);
  assert.equal(recordA.safetyEvent.classification, 'susar');
  assert.equal(recordA.safetyEvent.immediateEscalationRequired, true);
  assert.equal(recordA.safetyEvent.escalationStatus, 'required_ready');
  assert.equal(recordA.safetyEvent.clinicalResponseStatus, 'complete');
  assert.equal(recordA.safetyEvent.reportingStatus, 'complete');
  assert.equal(recordA.safetyEvent.notificationStatus, 'complete');
  assert.equal(recordA.safetyEvent.followUpStatus, 'pending');
  assert.equal(recordA.safetyEvent.closureStatus, 'open');
  assert.equal(recordA.safetyEvent.aiFinalAuthority, false);
  assert.equal(recordA.safetyEvent.exochainProductionClaim, false);
  assert.deepEqual(recordA.safetyEvent.requiredEscalationRoles, [
    'decision_forum',
    'principal_investigator',
    'site_quality_lead',
    'sponsor_safety_contact',
  ]);
  assert.equal(recordA.safetyEvent.safetyEventId, recordB.safetyEvent.safetyEventId);
  assert.equal(recordA.receipt.receiptId, recordB.receipt.receiptId);
  assert.equal(recordA.receipt.actionHash, recordB.receipt.actionHash);
  assert.equal(recordA.receipt.trustState, 'inactive');
  assert.equal(recordA.receipt.anchorPayload.artifactType, 'safety_event_record');
  assert.doesNotMatch(JSON.stringify(recordA), /Participant Alice|medical record|source document|raw event/iu);
});

test('non-serious AE can remain open without Decision Forum or CAPA when response rationale is documented', async () => {
  const { evaluateSafetyEventWorkflow } = await loadSafetyEvents();

  const result = evaluateSafetyEventWorkflow({
    ...susarInput(),
    safetyEvent: {
      ...susarInput().safetyEvent,
      eventRef: 'SAFETY-EVENT-2026-0005',
      classification: 'ae',
      serious: false,
      expectedness: 'expected',
      relatedness: 'not_related',
      severity: 'mild',
      resolutionAtHlc: null,
      reportEvidenceHashes: [],
      status: 'reported',
    },
    clinicalResponse: {
      required: false,
      status: 'not_required',
      rationaleHash: DIGEST_B,
    },
    reporting: {
      sponsor: { required: true, timelineRef: 'sponsor-ae-periodic', dueAtHlc: { physicalMs: 1790604800000, logical: 0 }, status: 'submitted', submittedAtHlc: { physicalMs: 1790003600000, logical: 0 }, evidenceHash: DIGEST_C },
      irb: { required: false, status: 'not_required', rationaleHash: DIGEST_D },
      regulatory: { required: false, status: 'not_required', rationaleHash: DIGEST_E },
    },
    notifications: [
      {
        party: 'principal_investigator',
        required: true,
        status: 'notified',
        notifiedAtHlc: { physicalMs: 1790000300000, logical: 0 },
        evidenceHash: DIGEST_B,
      },
    ],
    investigation: { required: false, status: 'not_required', rationaleHash: DIGEST_C },
    followUp: { required: false, status: 'not_required', rationaleHash: DIGEST_D },
    deviationLinkage: { required: false },
    capaLinkage: { required: false },
    decisionForum: null,
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.safetyEvent.immediateEscalationRequired, false);
  assert.equal(result.safetyEvent.escalationStatus, 'not_required');
  assert.equal(result.safetyEvent.clinicalResponseStatus, 'not_required');
  assert.equal(result.safetyEvent.investigationStatus, 'not_required');
  assert.equal(result.safetyEvent.followUpStatus, 'not_required');
  assert.equal(result.safetyEvent.capaRequired, false);
  assert.equal(result.safetyEvent.closureStatus, 'open');
  assert.deepEqual(result.safetyEvent.requiredEscalationRoles, ['principal_investigator']);
});

test('safety event closure requires complete reporting follow-up investigation and human governance', async () => {
  const { evaluateSafetyEventWorkflow } = await loadSafetyEvents();

  const result = evaluateSafetyEventWorkflow({
    ...susarInput(),
    safetyEvent: {
      ...susarInput().safetyEvent,
      status: 'closure_ready',
    },
    investigation: {
      required: true,
      status: 'complete',
      investigatorDid: 'did:exo:principal-investigator-alpha',
      planHash: DIGEST_E,
      openedAtHlc: { physicalMs: 1790006000000, logical: 0 },
      findingsHash: DIGEST_A,
      completedAtHlc: { physicalMs: 1790500000000, logical: 0 },
    },
    followUp: {
      required: true,
      status: 'complete',
      requiredReportCount: 2,
      completedReportCount: 2,
      reportHashes: [DIGEST_C, DIGEST_D],
      completedAtHlc: { physicalMs: 1790500000000, logical: 1 },
    },
    closureReview: {
      closedByDid: 'did:exo:principal-investigator-alpha',
      closureEvidenceHash: DIGEST_B,
      closedAtHlc: { physicalMs: 1790500001000, logical: 0 },
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-safety-closure-0004',
        workflowReceiptId: 'df-workflow-receipt-safety-closure-0004',
      },
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.safetyEvent.closureStatus, 'closed');
  assert.equal(result.closureReceipt.trustState, 'inactive');
  assert.equal(result.closureReceipt.exochainProductionClaim, false);
  assert.equal(result.closureReceipt.anchorPayload.artifactType, 'safety_event_closure');
});

test('safety event workflow fails closed for participant safety boundary defects', async () => {
  const { evaluateSafetyEventWorkflow } = await loadSafetyEvents();

  const cases = [
    {
      name: 'AI actor',
      mutate: (input) => ({ ...input, actor: { did: 'did:exo:ai-reviewer', kind: 'ai_agent' } }),
      reason: 'ai_final_authority_forbidden',
    },
    {
      name: 'tenant mismatch',
      mutate: (input) => ({ ...input, targetTenantId: 'tenant-other' }),
      reason: 'tenant_boundary_violation',
    },
    {
      name: 'participant code hash absent',
      mutate: (input) => ({ ...input, safetyEvent: { ...input.safetyEvent, participantCodeHash: null } }),
      reason: 'participant_code_hash_invalid',
    },
    {
      name: 'resolution before onset',
      mutate: (input) => ({
        ...input,
        safetyEvent: {
          ...input.safetyEvent,
          resolutionAtHlc: { physicalMs: 1789999999999, logical: 0 },
        },
      }),
      reason: 'resolution_time_precedes_onset',
    },
    {
      name: 'serious event response absent',
      mutate: (input) => ({ ...input, clinicalResponse: { required: true, status: 'pending' } }),
      reason: 'clinical_response_evidence_absent',
    },
    {
      name: 'clinical response completion before initiation',
      mutate: (input) => ({
        ...input,
        clinicalResponse: {
          ...input.clinicalResponse,
          initiatedAtHlc: { physicalMs: 1790000001000, logical: 1 },
          completedAtHlc: { physicalMs: 1790000001000, logical: 0 },
        },
      }),
      reason: 'clinical_response_evidence_absent',
    },
    {
      name: 'required sponsor report incomplete',
      mutate: (input) => ({ ...input, reporting: { ...input.reporting, sponsor: { required: true, status: 'pending', timelineRef: 'sponsor-sae-susar-expedited', dueAtHlc: { physicalMs: 1790086400000, logical: 0 } } } }),
      reason: 'sponsor_reporting_incomplete',
    },
    {
      name: 'required reporting decision absent',
      mutate: (input) => ({ ...input, reporting: { ...input.reporting, regulatory: { status: 'pending' } } }),
      reason: 'regulatory_reporting_incomplete',
    },
    {
      name: 'sponsor safety contact notification absent',
      mutate: (input) => ({
        ...input,
        notifications: input.notifications.filter((notification) => notification.party !== 'sponsor_safety_contact'),
      }),
      reason: 'sponsor_safety_contact_notification_incomplete',
    },
    {
      name: 'closure follow up incomplete',
      mutate: (input) => ({
        ...input,
        safetyEvent: { ...input.safetyEvent, status: 'closure_ready' },
        followUp: { required: true, status: 'pending', requiredReportCount: 2, completedReportCount: 1, reportHashes: [DIGEST_C] },
      }),
      reason: 'follow_up_incomplete',
    },
  ];

  for (const { name, mutate, reason } of cases) {
    const result = evaluateSafetyEventWorkflow(mutate(susarInput()));
    assert.equal(result.decision, 'denied', name);
    assert.equal(result.failClosed, true, name);
    assert.ok(result.reasons.includes(reason), `${name} should include ${reason}`);
    assert.equal(result.receipt, null, name);
  }
});

test('safety event workflow rejects raw participant or clinical event content before receipt creation', async () => {
  const { evaluateSafetyEventWorkflow, ProtectedContentError } = await loadSafetyEvents();

  assert.throws(
    () =>
      evaluateSafetyEventWorkflow({
        ...susarInput(),
        safetyEvent: {
          ...susarInput().safetyEvent,
          rawEventDetails: 'Participant Alice had a source document note here.',
        },
      }),
    ProtectedContentError,
  );
});
