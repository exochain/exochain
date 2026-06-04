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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const COMMUNICATION_CATEGORIES = new Set([
  'administrative_update',
  'consent_update',
  'material_new_information',
  'participant_rights_update',
  'protocol_update',
  'safety_update',
]);
const PARTICIPANT_STATUSES = new Set(['active', 'enrolled', 'follow_up', 'screened']);
const RECONSENT_STATUSES = new Set(['deferred', 'emergency_exception', 'not_required', 'reconsent_required']);
const REQUIRED_ACTION_BY_RECONSENT_STATUS = Object.freeze({
  deferred: 'hold_continuation_pending_reconsent_decision',
  emergency_exception: 'document_exception_and_notify_required_parties',
  not_required: 'continue_with_documented_update',
  reconsent_required: 'obtain_reconsent_before_continuation',
});
const RAW_COMMUNICATION_FIELDS = new Set([
  'communicationbody',
  'directparticipantmessage',
  'participantcommunicationbody',
  'participantname',
  'rawmessage',
  'rawparticipantcommunication',
  'rawparticipantmessage',
  'sourcedocumentbody',
  'verbatimparticipantresponse',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoCommunicationProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoCommunicationProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_COMMUNICATION_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`participant communication protected content field is not allowed at ${path}.${key}`);
    }
    assertNoCommunicationProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoCommunicationProtectedContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons, permissions, missingReason) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !permissions.some((permission) => hasAuthorityPermission(input?.authority, permission)), missingReason);
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateParticipant(input, reasons) {
  const participant = input?.participant;
  addReason(reasons, !hasText(participant?.participantCodeRecordId), 'participant_code_record_id_absent');
  addReason(reasons, !isDigest(participant?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(participant?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(participant?.siteRef), 'site_ref_absent');
  addReason(reasons, !PARTICIPANT_STATUSES.has(participant?.status), 'participant_status_invalid');
  addReason(reasons, !hasText(participant?.consentBailmentRef), 'consent_bailment_ref_absent');
}

function evaluateApprovedMaterial(communication, reasons) {
  const material = communication?.approvedMaterial;
  addReason(reasons, !hasText(material?.materialRef), 'participant_material_ref_absent');
  addReason(reasons, !hasText(material?.version), 'participant_material_version_absent');
  addReason(reasons, !isDigest(material?.materialArtifactHash), 'participant_material_artifact_hash_invalid');
  addReason(reasons, hlcTuple(material?.effectiveAtHlc) === null, 'participant_material_effective_time_invalid');

  if (communication?.participantFacing === true && communication?.iecIrbApprovalRequired === true) {
    addReason(reasons, material?.iecIrbApprovalStatus !== 'approved', 'participant_material_approval_not_approved');
    addReason(reasons, !isDigest(material?.iecIrbApprovalEvidenceHash), 'participant_material_approval_evidence_invalid');
    addReason(reasons, hlcTuple(material?.approvedAtHlc) === null, 'participant_material_approval_time_invalid');
    addReason(
      reasons,
      hlcTuple(material?.approvedAtHlc) !== null &&
        hlcTuple(material?.effectiveAtHlc) !== null &&
        !hlcAfterOrEqual(material.effectiveAtHlc, material.approvedAtHlc),
      'participant_material_effective_before_approval',
    );
  }
}

function evaluateCommunicationPlan(communication, reasons) {
  const plan = communication?.plan;
  addReason(reasons, !hasText(plan?.communicationPlanRef), 'communication_plan_ref_absent');
  addReason(reasons, sortedTextList(plan?.audienceRefs).length === 0, 'communication_audience_absent');
  addReason(reasons, sortedTextList(plan?.channelRefs).length === 0, 'communication_plan_channels_absent');
  addReason(reasons, sortedTextList(plan?.staffRoleRefs).length === 0, 'communication_staff_roles_absent');
  addReason(reasons, !isDigest(plan?.privacyBoundaryHash), 'communication_privacy_boundary_invalid');
}

function evaluateCommunicationStaff(communication, reasons) {
  const staff = communication?.staffReadiness;
  addReason(reasons, staff?.trained !== true, 'communication_staff_training_absent');
  addReason(reasons, staff?.delegated !== true, 'communication_staff_delegation_absent');
  addReason(reasons, !isDigest(staff?.trainingEvidenceHash), 'communication_staff_training_evidence_invalid');
  addReason(reasons, !hasText(staff?.delegationReceiptId), 'communication_staff_delegation_receipt_absent');
}

function evaluateCommunicationDissemination(input, reasons) {
  const communication = input?.communication;
  const dissemination = communication?.dissemination;
  const deliveredChannels = sortedTextList(dissemination?.channelRefs);
  const planChannels = new Set(sortedTextList(communication?.plan?.channelRefs));

  addReason(reasons, hlcTuple(dissemination?.deliveredAtHlc) === null, 'communication_delivery_time_invalid');
  addReason(reasons, !isDigest(dissemination?.deliveryEvidenceHash), 'communication_delivery_evidence_invalid');
  addReason(reasons, !hasText(dissemination?.deliveredByDid), 'communication_delivered_by_absent');
  addReason(reasons, hasText(dissemination?.deliveredByDid) && dissemination.deliveredByDid !== input?.actor?.did, 'communication_delivered_by_actor_mismatch');
  addReason(reasons, deliveredChannels.length === 0, 'communication_delivery_channels_absent');
  addReason(reasons, deliveredChannels.some((channel) => !planChannels.has(channel)), 'communication_channel_not_authorized');
  addReason(reasons, dissemination?.languageAccommodationDocumented !== true, 'language_accommodation_absent');
  addReason(reasons, dissemination?.accessibilityAccommodationDocumented !== true, 'accessibility_accommodation_absent');
  addReason(reasons, dissemination?.questionsOpportunityProvided !== true, 'question_opportunity_absent');
  addReason(reasons, dissemination?.participantCopyDelivered !== true, 'participant_copy_delivery_absent');
  addReason(reasons, dissemination?.nonCoercive !== true, 'non_coercion_attestation_absent');
  addReason(
    reasons,
    hlcTuple(dissemination?.deliveredAtHlc) !== null &&
      hlcTuple(communication?.approvedMaterial?.effectiveAtHlc) !== null &&
      !hlcAfterOrEqual(dissemination.deliveredAtHlc, communication.approvedMaterial.effectiveAtHlc),
    'communication_delivery_before_material_effective',
  );
}

function evaluateCommunication(input, reasons) {
  const communication = input?.communication;
  addReason(reasons, !hasText(communication?.communicationRef), 'communication_ref_absent');
  addReason(reasons, !COMMUNICATION_CATEGORIES.has(communication?.category), 'communication_category_invalid');
  addReason(reasons, sortedTextList(communication?.topicRefs).length === 0, 'communication_topics_absent');
  addReason(reasons, communication?.participantFacing !== true, 'participant_facing_communication_required');
  addReason(reasons, typeof communication?.iecIrbApprovalRequired !== 'boolean', 'iec_irb_approval_requirement_invalid');
  evaluateApprovedMaterial(communication, reasons);
  evaluateCommunicationPlan(communication, reasons);
  evaluateCommunicationStaff(communication, reasons);
  evaluateCommunicationDissemination(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function requiresReconsentDetermination(communication) {
  const topics = new Set(sortedTextList(communication?.topicRefs));
  return (
    communication?.category === 'material_new_information' ||
    communication?.category === 'consent_update' ||
    topics.has('new_safety_information') ||
    topics.has('protocol_amendment_consent_change')
  );
}

function communicationRecordId(input) {
  const communication = input?.communication;
  return `cmpcomm_${sha256Hex({
    communicationRef: communication?.communicationRef ?? null,
    deliveredAtHlc: communication?.dissemination?.deliveredAtHlc ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildCommunicationRecord(input, status, receiptId = null) {
  const communication = input?.communication;
  const material = communication?.approvedMaterial;

  return {
    schema: 'cybermedica.participant_communication_record.v1',
    communicationRecordId: communicationRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeRecordId: input?.participant?.participantCodeRecordId ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    protocolRef: input?.participant?.protocolRef ?? null,
    siteRef: input?.participant?.siteRef ?? null,
    status,
    category: communication?.category ?? null,
    topicRefs: sortedTextList(communication?.topicRefs),
    communicationPlanRef: communication?.plan?.communicationPlanRef ?? null,
    audienceRefs: sortedTextList(communication?.plan?.audienceRefs),
    channelRefs: sortedTextList(communication?.dissemination?.channelRefs),
    staffRoleRefs: sortedTextList(communication?.plan?.staffRoleRefs),
    staffTrained: communication?.staffReadiness?.trained === true,
    staffDelegated: communication?.staffReadiness?.delegated === true,
    participantFacing: communication?.participantFacing === true,
    iecIrbApprovalRequired: communication?.iecIrbApprovalRequired === true,
    approvedForParticipantUse:
      communication?.iecIrbApprovalRequired !== true || material?.iecIrbApprovalStatus === 'approved',
    materialRef: material?.materialRef ?? null,
    materialVersion: material?.version ?? null,
    materialArtifactHash: material?.materialArtifactHash ?? null,
    deliveredAtHlc: communication?.dissemination?.deliveredAtHlc ?? null,
    updatedInformationDisseminated: status === 'communicated',
    reconsentDeterminationRequired: requiresReconsentDetermination(communication),
    consentBailmentRef: input?.participant?.consentBailmentRef ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createCommunicationReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_communication',
    artifactVersion: `${record.communicationRecordId}@${record.category}`,
    classification: 'participant_communication_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.communication.dissemination.deliveredAtHlc,
    sensitivityTags: ['participant_communication', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.participant_communications',
    tenantId: input.tenantId,
  });
}

export function recordParticipantCommunication(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(
    input,
    reasons,
    ['communicate_with_participants', 'manage_consent_materials', 'write'],
    'participant_communication_authority_missing',
  );
  evaluateParticipant(input, reasons);
  evaluateCommunication(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.participant_communication_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      communicationRecord: buildCommunicationRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildCommunicationRecord(input, 'communicated');
  const artifactHash = sha256Hex({
    audienceRefs: record.audienceRefs,
    channelRefs: record.channelRefs,
    communicationRecordId: record.communicationRecordId,
    consentBailmentRef: record.consentBailmentRef,
    deliveryEvidenceHash: input.communication.dissemination.deliveryEvidenceHash,
    materialArtifactHash: record.materialArtifactHash,
    participantCodeHash: record.participantCodeHash,
    protocolRef: record.protocolRef,
    staffDelegationReceiptId: input.communication.staffReadiness.delegationReceiptId,
    tenantId: input.tenantId,
    topicRefs: record.topicRefs,
  });
  const receipt = createCommunicationReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_communication_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    communicationRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}

function evaluateUpdatedInformation(input, reasons) {
  const updatedInformation = input?.updatedInformation;
  addReason(reasons, typeof updatedInformation?.materialNewInformation !== 'boolean', 'material_new_information_flag_invalid');
  addReason(reasons, !isDigest(updatedInformation?.sourceArtifactHash), 'updated_information_source_hash_invalid');
  addReason(reasons, hlcTuple(updatedInformation?.discoveredAtHlc) === null, 'updated_information_discovery_time_invalid');
  addReason(
    reasons,
    !hasText(updatedInformation?.communicationRecordId) || !hasText(updatedInformation?.communicationReceiptId),
    'updated_information_communication_absent',
  );
  addReason(reasons, hlcTuple(updatedInformation?.communicationDeliveredAtHlc) === null, 'communication_delivery_time_invalid');
  addReason(reasons, !isDigest(updatedInformation?.communicationEvidenceHash), 'communication_evidence_hash_invalid');
  addReason(reasons, sortedTextList(updatedInformation?.impactRefs).length === 0, 'updated_information_impact_refs_absent');
  addReason(
    reasons,
    hlcTuple(updatedInformation?.communicationDeliveredAtHlc) !== null &&
      hlcTuple(updatedInformation?.discoveredAtHlc) !== null &&
      !hlcAfterOrEqual(updatedInformation.communicationDeliveredAtHlc, updatedInformation.discoveredAtHlc),
    'communication_delivered_before_information_discovery',
  );
}

function evaluateDecisionForumIfRequired(determination, reasons) {
  const forum = determination?.decisionForum;
  if (forum?.required !== true) {
    return;
  }
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function evaluateReconsentDetermination(input, reasons) {
  const determination = input?.determination;
  addReason(reasons, !RECONSENT_STATUSES.has(determination?.status), 'reconsent_status_invalid');
  addReason(
    reasons,
    input?.updatedInformation?.materialNewInformation === true && determination?.status === 'not_required',
    'material_new_information_requires_reconsent_or_hold',
  );
  addReason(reasons, hlcTuple(determination?.determinedAtHlc) === null, 'reconsent_determination_time_invalid');
  addReason(
    reasons,
    hlcTuple(determination?.determinedAtHlc) !== null &&
      hlcTuple(input?.updatedInformation?.communicationDeliveredAtHlc) !== null &&
      !hlcAfterOrEqual(determination.determinedAtHlc, input.updatedInformation.communicationDeliveredAtHlc),
    'reconsent_determination_before_communication',
  );
  addReason(reasons, !hasText(determination?.humanReviewerDid), 'human_reconsent_reviewer_absent');
  addReason(reasons, determination?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(determination?.rationaleHash), 'reconsent_rationale_hash_invalid');
  addReason(reasons, determination?.phiBoundaryAttested !== true, 'phi_boundary_unattested');

  if (determination?.status === 'reconsent_required') {
    addReason(reasons, !hasText(determination?.consentMaterialId), 'reconsent_material_id_absent');
    addReason(reasons, !hasText(determination?.consentMaterialVersion), 'reconsent_material_version_absent');
    addReason(reasons, !hasText(determination?.consentMaterialReceiptId), 'reconsent_material_receipt_absent');
    addReason(reasons, !isDigest(determination?.reconsentPlanHash), 'reconsent_plan_hash_invalid');
    addReason(reasons, hlcTuple(determination?.dueAtHlc) === null, 'reconsent_due_time_invalid');
    addReason(reasons, determination?.participantContinuationGate !== 'blocked_until_reconsent', 'continuation_gate_must_block_until_reconsent');
    addReason(
      reasons,
      hlcTuple(determination?.dueAtHlc) !== null &&
        hlcTuple(determination?.determinedAtHlc) !== null &&
        !hlcAfterOrEqual(determination.dueAtHlc, determination.determinedAtHlc),
      'reconsent_due_before_determination',
    );
  }

  if (determination?.status === 'not_required') {
    addReason(reasons, determination?.participantContinuationGate !== 'continue_with_documented_update', 'continuation_gate_not_documented_update');
  }

  if (determination?.status === 'deferred') {
    addReason(reasons, !isDigest(determination?.reconsentPlanHash), 'deferred_reconsent_plan_hash_invalid');
    addReason(reasons, determination?.participantContinuationGate !== 'hold_pending_reconsent_decision', 'deferred_continuation_gate_invalid');
  }

  if (determination?.status === 'emergency_exception') {
    addReason(reasons, !isDigest(determination?.exceptionPolicyHash), 'emergency_exception_policy_hash_invalid');
    addReason(reasons, determination?.participantContinuationGate !== 'exception_documented_required_notifications', 'emergency_exception_gate_invalid');
  }

  evaluateDecisionForumIfRequired(determination, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function reconsentRecordId(input) {
  return `cmpreconsent_${sha256Hex({
    determinedAtHlc: input?.determination?.determinedAtHlc ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    sourceArtifactHash: input?.updatedInformation?.sourceArtifactHash ?? null,
    status: input?.determination?.status ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function requiredActionForDetermination(determination) {
  return REQUIRED_ACTION_BY_RECONSENT_STATUS[determination?.status] ?? 'blocked';
}

function continuationAllowedForDetermination(determination) {
  return determination?.status === 'not_required' && determination?.participantContinuationGate === 'continue_with_documented_update';
}

function buildReconsentRecord(input, status, receiptId = null) {
  const updatedInformation = input?.updatedInformation;
  const determination = input?.determination;

  return {
    schema: 'cybermedica.reconsent_determination_record.v1',
    reconsentRecordId: reconsentRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeRecordId: input?.participant?.participantCodeRecordId ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    protocolRef: input?.participant?.protocolRef ?? null,
    siteRef: input?.participant?.siteRef ?? null,
    status,
    materialNewInformation: updatedInformation?.materialNewInformation === true,
    impactRefs: sortedTextList(updatedInformation?.impactRefs),
    communicationDocumented: hasText(updatedInformation?.communicationRecordId) && hasText(updatedInformation?.communicationReceiptId),
    communicationRecordId: updatedInformation?.communicationRecordId ?? null,
    communicationReceiptId: updatedInformation?.communicationReceiptId ?? null,
    determinedAtHlc: determination?.determinedAtHlc ?? null,
    humanReviewerDid: determination?.humanReviewerDid ?? null,
    continuationAllowed: status === 'blocked' ? false : continuationAllowedForDetermination(determination),
    requiredAction: status === 'blocked' ? 'blocked' : requiredActionForDetermination(determination),
    consentMaterialId: determination?.consentMaterialId ?? null,
    consentMaterialVersion: determination?.consentMaterialVersion ?? null,
    consentMaterialReceiptId: determination?.consentMaterialReceiptId ?? null,
    dueAtHlc: determination?.dueAtHlc ?? null,
    decisionForumRequired: determination?.decisionForum?.required === true,
    consentBailmentRef: input?.participant?.consentBailmentRef ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createReconsentReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'reconsent_determination',
    artifactVersion: `${record.participantCodeRecordId}@${record.status}`,
    classification: 'reconsent_determination_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.determination.determinedAtHlc,
    sensitivityTags: ['reconsent', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.participant_communications',
    tenantId: input.tenantId,
  });
}

export function determineReconsentNeed(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons, ['determine_reconsent', 'manage_consent_materials', 'write'], 'reconsent_authority_missing');
  evaluateParticipant(input, reasons);
  evaluateUpdatedInformation(input, reasons);
  evaluateReconsentDetermination(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.reconsent_determination_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      reconsentRecord: buildReconsentRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildReconsentRecord(input, input.determination.status);
  const artifactHash = sha256Hex({
    communicationEvidenceHash: input.updatedInformation.communicationEvidenceHash,
    communicationReceiptId: record.communicationReceiptId,
    consentBailmentRef: record.consentBailmentRef,
    consentMaterialReceiptId: record.consentMaterialReceiptId,
    impactRefs: record.impactRefs,
    materialNewInformation: record.materialNewInformation,
    participantCodeHash: record.participantCodeHash,
    rationaleHash: input.determination.rationaleHash,
    reconsentPlanHash: input.determination.reconsentPlanHash ?? null,
    reconsentRecordId: record.reconsentRecordId,
    requiredAction: record.requiredAction,
    sourceArtifactHash: input.updatedInformation.sourceArtifactHash,
    tenantId: input.tenantId,
  });
  const receipt = createReconsentReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.reconsent_determination_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    reconsentRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
