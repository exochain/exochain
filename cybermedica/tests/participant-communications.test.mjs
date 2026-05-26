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

async function loadParticipantCommunications() {
  try {
    return await import('../src/participant-communications.mjs');
  } catch (error) {
    assert.fail(`CyberMedica participant-communications module must exist and load: ${error.message}`);
  }
}

function participantCommunicationInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-designee-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'communicate_with_participants'],
      authorityChainHash: DIGEST_F,
    },
    participant: {
      participantCodeRecordId: 'cmpcode_active_alpha',
      participantCodeHash: DIGEST_A,
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'enrolled',
      consentBailmentRef: 'bailment-participant-alpha',
    },
    communication: {
      communicationRef: 'participant-update-cardio-alpha-002',
      category: 'material_new_information',
      topicRefs: ['new_safety_information', 'protocol_amendment_consent_change'],
      participantFacing: true,
      iecIrbApprovalRequired: true,
      approvedMaterial: {
        materialRef: 'participant-update-cardio-alpha-v2',
        version: 'v2.0',
        materialArtifactHash: DIGEST_B,
        iecIrbApprovalStatus: 'approved',
        iecIrbApprovalEvidenceHash: DIGEST_C,
        approvedAtHlc: { physicalMs: 1796000000000, logical: 0 },
        effectiveAtHlc: { physicalMs: 1796000000000, logical: 1 },
      },
      plan: {
        communicationPlanRef: 'participant-communication-plan-alpha',
        audienceRefs: ['active_participants', 'participants_in_follow_up'],
        channelRefs: ['secure_portal', 'site_visit'],
        staffRoleRefs: ['consent_designee', 'principal_investigator'],
        privacyBoundaryHash: DIGEST_D,
      },
      staffReadiness: {
        trained: true,
        delegated: true,
        trainingEvidenceHash: DIGEST_E,
        delegationReceiptId: 'cmdel_participant_communication_alpha',
      },
      dissemination: {
        deliveredAtHlc: { physicalMs: 1796100000000, logical: 0 },
        deliveryEvidenceHash: DIGEST_1,
        deliveredByDid: 'did:exo:consent-designee-alpha',
        channelRefs: ['site_visit', 'secure_portal'],
        languageAccommodationDocumented: true,
        accessibilityAccommodationDocumented: true,
        questionsOpportunityProvided: true,
        participantCopyDelivered: true,
        nonCoercive: true,
      },
    },
    custodyDigest: DIGEST_2,
  };
}

function reconsentDeterminationInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:participant-rights-lead-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'determine_reconsent'],
      authorityChainHash: DIGEST_F,
    },
    participant: {
      participantCodeRecordId: 'cmpcode_active_alpha',
      participantCodeHash: DIGEST_A,
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'enrolled',
      consentBailmentRef: 'bailment-participant-alpha',
    },
    updatedInformation: {
      materialNewInformation: true,
      sourceArtifactHash: DIGEST_B,
      discoveredAtHlc: { physicalMs: 1796200000000, logical: 0 },
      communicationRecordId: 'cmpcomm_participant_update_alpha',
      communicationReceiptId: 'cmr_participant_update_alpha',
      communicationDeliveredAtHlc: { physicalMs: 1796300000000, logical: 0 },
      communicationEvidenceHash: DIGEST_C,
      impactRefs: ['known_risk_change', 'new_safety_information'],
    },
    determination: {
      status: 'reconsent_required',
      determinedAtHlc: { physicalMs: 1796400000000, logical: 0 },
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      aiFinalAuthority: false,
      rationaleHash: DIGEST_D,
      consentMaterialId: 'cmicf_cardio_alpha_v3_2',
      consentMaterialVersion: 'v3.2',
      consentMaterialReceiptId: 'cmr_consent_material_v3_2',
      reconsentPlanHash: DIGEST_E,
      dueAtHlc: { physicalMs: 1796486400000, logical: 0 },
      participantContinuationGate: 'blocked_until_reconsent',
      phiBoundaryAttested: true,
      decisionForum: {
        required: false,
        verified: false,
        decisionId: null,
        workflowReceiptId: null,
      },
    },
    custodyDigest: DIGEST_2,
  };
}

test('participant communication records updated information dissemination as inactive metadata receipts', async () => {
  const { recordParticipantCommunication } = await loadParticipantCommunications();

  const resultA = recordParticipantCommunication(participantCommunicationInput());
  const resultB = recordParticipantCommunication({
    ...participantCommunicationInput(),
    communication: {
      ...participantCommunicationInput().communication,
      topicRefs: [...participantCommunicationInput().communication.topicRefs].reverse(),
      plan: {
        ...participantCommunicationInput().communication.plan,
        audienceRefs: [...participantCommunicationInput().communication.plan.audienceRefs].reverse(),
        channelRefs: [...participantCommunicationInput().communication.plan.channelRefs].reverse(),
        staffRoleRefs: [...participantCommunicationInput().communication.plan.staffRoleRefs].reverse(),
      },
      dissemination: {
        ...participantCommunicationInput().communication.dissemination,
        channelRefs: [...participantCommunicationInput().communication.dissemination.channelRefs].reverse(),
      },
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.communicationRecord.status, 'communicated');
  assert.equal(resultA.communicationRecord.participantCodeHash, DIGEST_A);
  assert.equal(resultA.communicationRecord.updatedInformationDisseminated, true);
  assert.equal(resultA.communicationRecord.reconsentDeterminationRequired, true);
  assert.deepEqual(resultA.communicationRecord.channelRefs, ['secure_portal', 'site_visit']);
  assert.equal(resultA.communicationRecord.communicationRecordId, resultB.communicationRecord.communicationRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'participant_communication');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|medical record|raw participant|email|phone/iu);

  const protocolUpdate = recordParticipantCommunication({
    ...participantCommunicationInput(),
    communication: {
      ...participantCommunicationInput().communication,
      category: 'protocol_update',
      topicRefs: ['protocol_amendment_consent_change'],
      dissemination: {
        ...participantCommunicationInput().communication.dissemination,
        deliveredAtHlc: { physicalMs: 1796000000000, logical: 1 },
      },
    },
  });

  assert.equal(protocolUpdate.decision, 'permitted');
  assert.equal(protocolUpdate.communicationRecord.reconsentDeterminationRequired, true);
});

test('reconsent determination blocks continuation after material new information until reconsent is complete', async () => {
  const { determineReconsentNeed } = await loadParticipantCommunications();

  const resultA = determineReconsentNeed(reconsentDeterminationInput());
  const resultB = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    updatedInformation: {
      ...reconsentDeterminationInput().updatedInformation,
      impactRefs: [...reconsentDeterminationInput().updatedInformation.impactRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.reconsentRecord.status, 'reconsent_required');
  assert.equal(resultA.reconsentRecord.continuationAllowed, false);
  assert.equal(resultA.reconsentRecord.requiredAction, 'obtain_reconsent_before_continuation');
  assert.equal(resultA.reconsentRecord.communicationDocumented, true);
  assert.equal(resultA.reconsentRecord.consentMaterialReceiptId, 'cmr_consent_material_v3_2');
  assert.equal(resultA.reconsentRecord.reconsentRecordId, resultB.reconsentRecord.reconsentRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'reconsent_determination');
  assert.equal(resultA.receipt.trustState, 'inactive');
});

test('non material participant updates can document human no reconsent determinations', async () => {
  const { determineReconsentNeed } = await loadParticipantCommunications();

  const result = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    updatedInformation: {
      ...reconsentDeterminationInput().updatedInformation,
      materialNewInformation: false,
      impactRefs: ['administrative_update'],
    },
    determination: {
      ...reconsentDeterminationInput().determination,
      status: 'not_required',
      consentMaterialId: null,
      consentMaterialVersion: null,
      consentMaterialReceiptId: null,
      reconsentPlanHash: null,
      dueAtHlc: null,
      participantContinuationGate: 'continue_with_documented_update',
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.reconsentRecord.status, 'not_required');
  assert.equal(result.reconsentRecord.continuationAllowed, true);
  assert.equal(result.reconsentRecord.requiredAction, 'continue_with_documented_update');
  assert.equal(result.reconsentRecord.materialNewInformation, false);
});

test('participant communication and reconsent controls fail closed for unsafe evidence and raw content', async () => {
  const { ProtectedContentError, determineReconsentNeed, recordParticipantCommunication } = await loadParticipantCommunications();

  const communicationDenied = recordParticipantCommunication({
    ...participantCommunicationInput(),
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    communication: {
      ...participantCommunicationInput().communication,
      approvedMaterial: {
        ...participantCommunicationInput().communication.approvedMaterial,
        iecIrbApprovalStatus: 'pending',
        iecIrbApprovalEvidenceHash: '',
      },
      staffReadiness: {
        ...participantCommunicationInput().communication.staffReadiness,
        trained: false,
        delegationReceiptId: '',
      },
      dissemination: {
        ...participantCommunicationInput().communication.dissemination,
        questionsOpportunityProvided: false,
        deliveredAtHlc: { physicalMs: 1796000000000, logical: 0 },
      },
    },
  });

  assert.equal(communicationDenied.decision, 'denied');
  assert.equal(communicationDenied.failClosed, true);
  assert.equal(communicationDenied.communicationRecord.status, 'blocked');
  assert.equal(communicationDenied.receipt, null);
  assert.match(communicationDenied.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(communicationDenied.reasons.join('|'), /participant_material_approval_not_approved/);
  assert.match(communicationDenied.reasons.join('|'), /communication_staff_training_absent/);
  assert.match(communicationDenied.reasons.join('|'), /question_opportunity_absent/);
  assert.match(communicationDenied.reasons.join('|'), /communication_delivery_before_material_effective/);

  const reconsentDenied = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    updatedInformation: {
      ...reconsentDeterminationInput().updatedInformation,
      communicationRecordId: '',
      communicationDeliveredAtHlc: { physicalMs: 1796199999999, logical: 0 },
    },
    determination: {
      ...reconsentDeterminationInput().determination,
      humanReviewerDid: '',
      aiFinalAuthority: true,
      consentMaterialReceiptId: '',
      dueAtHlc: { physicalMs: 1796399999999, logical: 0 },
      phiBoundaryAttested: false,
    },
  });

  assert.equal(reconsentDenied.decision, 'denied');
  assert.equal(reconsentDenied.failClosed, true);
  assert.equal(reconsentDenied.reconsentRecord.status, 'blocked');
  assert.equal(reconsentDenied.receipt, null);
  assert.match(reconsentDenied.reasons.join('|'), /updated_information_communication_absent/);
  assert.match(reconsentDenied.reasons.join('|'), /communication_delivered_before_information_discovery/);
  assert.match(reconsentDenied.reasons.join('|'), /human_reconsent_reviewer_absent/);
  assert.match(reconsentDenied.reasons.join('|'), /reconsent_material_receipt_absent/);
  assert.match(reconsentDenied.reasons.join('|'), /reconsent_due_before_determination/);
  assert.match(reconsentDenied.reasons.join('|'), /phi_boundary_unattested/);

  assert.throws(
    () =>
      recordParticipantCommunication({
        ...participantCommunicationInput(),
        communication: { ...participantCommunicationInput().communication, rawParticipantCommunication: 'call Participant Alice at 555-1212' },
      }),
    ProtectedContentError,
  );
});

test('reconsent determination records deferred and emergency exception branches', async () => {
  const { determineReconsentNeed } = await loadParticipantCommunications();

  const deferred = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    determination: {
      ...reconsentDeterminationInput().determination,
      status: 'deferred',
      consentMaterialId: null,
      consentMaterialVersion: null,
      consentMaterialReceiptId: null,
      dueAtHlc: null,
      participantContinuationGate: 'hold_pending_reconsent_decision',
    },
  });

  assert.equal(deferred.decision, 'permitted');
  assert.equal(deferred.reconsentRecord.status, 'deferred');
  assert.equal(deferred.reconsentRecord.continuationAllowed, false);
  assert.equal(deferred.reconsentRecord.requiredAction, 'hold_continuation_pending_reconsent_decision');

  const emergencyException = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    determination: {
      ...reconsentDeterminationInput().determination,
      status: 'emergency_exception',
      consentMaterialId: null,
      consentMaterialVersion: null,
      consentMaterialReceiptId: null,
      reconsentPlanHash: null,
      dueAtHlc: null,
      exceptionPolicyHash: DIGEST_1,
      participantContinuationGate: 'exception_documented_required_notifications',
    },
  });

  assert.equal(emergencyException.decision, 'permitted');
  assert.equal(emergencyException.reconsentRecord.status, 'emergency_exception');
  assert.equal(emergencyException.reconsentRecord.requiredAction, 'document_exception_and_notify_required_parties');

  const deniedDeferred = determineReconsentNeed({
    ...reconsentDeterminationInput(),
    determination: {
      ...reconsentDeterminationInput().determination,
      status: 'deferred',
      determinedAtHlc: { physicalMs: 1796400000000, logical: -1 },
      reconsentPlanHash: '',
      participantContinuationGate: 'continue_with_documented_update',
    },
  });

  assert.equal(deniedDeferred.decision, 'denied');
  assert.match(deniedDeferred.reasons.join('|'), /reconsent_determination_time_invalid/);
  assert.match(deniedDeferred.reasons.join('|'), /deferred_reconsent_plan_hash_invalid/);
  assert.match(deniedDeferred.reasons.join('|'), /deferred_continuation_gate_invalid/);
});
