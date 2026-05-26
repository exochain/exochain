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
const REQUIRED_PERMISSION = 'manage_training_gap';
const GAP_SCHEMA = 'cybermedica.staff_training_gap_management.v1';
const DECISION_SCHEMA = 'cybermedica.staff_training_gap_management_decision.v1';

const PROCEDURE_STEPS = Object.freeze([
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

const RAW_TRAINING_GAP_FIELDS = new Set([
  'body',
  'commentary',
  'content',
  'freetext',
  'freetextnote',
  'rawassessment',
  'rawcompetencynote',
  'rawcompletionevidence',
  'rawgap',
  'rawgapnarrative',
  'rawnotification',
  'rawsource',
  'rawsourcedata',
  'rawtrainingcontent',
  'rawtrainingnarrative',
  'reviewnotes',
  'sourcedocumentbody',
  'trainingbody',
  'trainingcontent',
  'trainingnarrative',
]);

const SECRET_TRAINING_GAP_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRawTrainingGapContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawTrainingGapContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_TRAINING_GAP_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw staff training gap field is not allowed at ${path}.${key}`);
    }
    if (SECRET_TRAINING_GAP_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`staff training gap secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawTrainingGapContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawTrainingGapContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function uniqueReasons(reasons) {
  return uniqueSorted(reasons);
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.siteId), 'site_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_training_gap_reviewer_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent' || input?.aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'training_gap_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateTrainingMatrix(matrix, reasons) {
  addReason(reasons, matrix?.verified !== true, 'training_matrix_unverified');
  addReason(reasons, matrix?.status !== 'approved', 'training_matrix_not_approved');
  addReason(reasons, !hasText(matrix?.receiptId), 'training_matrix_receipt_absent');
  addReason(reasons, matrix?.humanGate?.verified !== true, 'training_matrix_human_gate_unverified');
  addReason(reasons, matrix?.quorum?.status !== 'met', 'training_matrix_quorum_not_met');
  addReason(reasons, matrix?.openChallenge === true, 'training_matrix_challenge_open');
}

function evaluateGap(input, reasons) {
  const gap = input?.gap;
  if (gap === null || typeof gap !== 'object') {
    reasons.push('training_gap_absent');
    return;
  }

  addReason(reasons, !hasText(gap.gapId), 'training_gap_id_absent');
  addReason(reasons, !hasText(gap.requirementId), 'training_requirement_id_absent');
  addReason(reasons, !hasText(gap.gapReason), 'training_gap_reason_absent');
  addReason(reasons, !hasText(gap.actorDid), 'training_gap_actor_absent');
  addReason(reasons, !hasText(gap.role), 'training_gap_role_absent');
  addReason(reasons, !hasText(gap.controlledAction), 'controlled_action_absent');
  addReason(reasons, gap.status !== 'closed', 'training_gap_not_closed');
  addReason(reasons, hlcTuple(gap.openedAtHlc) === null, 'training_gap_open_time_invalid');
  addReason(reasons, hlcTuple(gap.closedAtHlc) === null, 'training_gap_close_time_invalid');
  addReason(reasons, hlcBefore(gap.closedAtHlc, gap.openedAtHlc), 'training_gap_closed_before_opened');
  addReason(reasons, hlcAfter(gap.closedAtHlc, input?.checkedAtHlc), 'training_gap_closed_after_check');
  addReason(reasons, !isDigest(gap.evidenceHash), 'training_gap_evidence_hash_invalid');
  addReason(reasons, gap.metadataOnly !== true, 'training_gap_metadata_boundary_invalid');
  addReason(reasons, gap.protectedContentExcluded !== true, 'training_gap_protected_boundary_invalid');
}

function evaluateNotification(input, reasons) {
  const notification = input?.notification;
  addReason(reasons, notification?.staffNotified !== true, 'staff_notification_missing');
  addReason(reasons, notification?.supervisorNotified !== true, 'supervisor_notification_missing');
  addReason(reasons, !isDigest(notification?.notificationEvidenceHash), 'notification_evidence_hash_invalid');
  addReason(reasons, hlcTuple(notification?.notifiedAtHlc) === null, 'notification_time_invalid');
  addReason(reasons, hlcBefore(notification?.notifiedAtHlc, input?.gap?.openedAtHlc), 'notification_before_gap_opened');
  addReason(reasons, hlcAfter(notification?.notifiedAtHlc, input?.checkedAtHlc), 'notification_after_check');
  addReason(reasons, notification?.metadataOnly !== true, 'notification_metadata_boundary_invalid');
}

function evaluateAssignment(input, reasons) {
  const assignment = input?.assignment;
  addReason(reasons, !hasText(assignment?.assignedTrainingRef), 'assigned_training_ref_absent');
  addReason(reasons, !hasText(assignment?.trainerDid), 'trainer_did_absent');
  addReason(reasons, !hasText(assignment?.supervisorDid), 'supervisor_did_absent');
  addReason(reasons, !isDigest(assignment?.assignmentEvidenceHash), 'assignment_evidence_hash_invalid');
  addReason(reasons, hlcTuple(assignment?.assignedAtHlc) === null, 'assignment_time_invalid');
  addReason(reasons, hlcTuple(assignment?.dueAtHlc) === null, 'training_due_time_invalid');
  addReason(reasons, hlcBefore(assignment?.assignedAtHlc, input?.gap?.openedAtHlc), 'training_assignment_before_gap_opened');
  addReason(reasons, hlcBefore(assignment?.dueAtHlc, assignment?.assignedAtHlc), 'training_due_before_assignment');
  addReason(reasons, hlcAfter(assignment?.assignedAtHlc, input?.checkedAtHlc), 'training_assignment_after_check');
}

function evaluateCompletion(input, reasons) {
  const completion = input?.completion;
  addReason(reasons, completion?.status !== 'completed', 'training_completion_not_completed');
  addReason(reasons, !hasText(completion?.trainingRecordRef), 'training_record_ref_absent');
  addReason(reasons, !isDigest(completion?.trainingRecordHash), 'training_record_hash_invalid');
  addReason(reasons, !hasText(completion?.evidenceType), 'training_evidence_type_absent');
  addReason(reasons, !Number.isSafeInteger(completion?.completedVersion), 'training_completed_version_invalid');
  addReason(reasons, !Number.isSafeInteger(completion?.requiredVersion), 'training_required_version_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(completion?.completedVersion) &&
      Number.isSafeInteger(completion?.requiredVersion) &&
      completion.completedVersion < completion.requiredVersion,
    'training_version_stale',
  );
  addReason(reasons, hlcTuple(completion?.completedAtHlc) === null, 'training_completion_time_invalid');
  addReason(reasons, hlcBefore(completion?.completedAtHlc, input?.assignment?.assignedAtHlc), 'training_completion_before_assignment');
  addReason(reasons, hlcAfter(completion?.completedAtHlc, input?.checkedAtHlc), 'training_completion_after_check');
}

function evaluateAssessment(input, reasons) {
  const assessment = input?.assessment;
  if (assessment?.required !== true) {
    return;
  }

  addReason(reasons, assessment.status !== 'passed', 'assessment_not_passed');
  addReason(reasons, assessment.verifiedByHuman !== true, 'assessment_human_verification_absent');
  addReason(reasons, !hasText(assessment.assessorDid), 'assessment_assessor_absent');
  addReason(reasons, !isDigest(assessment.assessmentEvidenceHash), 'assessment_evidence_hash_invalid');
  addReason(reasons, hlcTuple(assessment.assessedAtHlc) === null, 'assessment_time_invalid');
  addReason(reasons, hlcBefore(assessment.assessedAtHlc, input?.completion?.completedAtHlc), 'assessment_before_training_completion');
  addReason(reasons, hlcAfter(assessment.assessedAtHlc, input?.checkedAtHlc), 'assessment_after_check');
}

function evaluateCompetence(input, reasons) {
  const competence = input?.competenceVerification;
  addReason(reasons, competence?.verified !== true, 'competence_verification_absent');
  addReason(reasons, competence?.humanGate?.verified !== true, 'competence_human_gate_unverified');
  addReason(reasons, !hasText(competence?.verifiedByDid), 'competence_verifier_absent');
  addReason(reasons, !isDigest(competence?.competencyEvidenceHash), 'competence_evidence_hash_invalid');
  addReason(reasons, hlcTuple(competence?.verifiedAtHlc) === null, 'competence_verification_time_invalid');
  addReason(reasons, hlcBefore(competence?.verifiedAtHlc, input?.assessment?.assessedAtHlc), 'competence_before_assessment');
  addReason(reasons, hlcAfter(competence?.verifiedAtHlc, input?.checkedAtHlc), 'competence_after_check');
}

function evaluateRecordUpdate(input, reasons) {
  const update = input?.trainingRecordUpdate;
  addReason(reasons, update?.supersedesGap !== true, 'training_record_update_not_gap_superseding');
  addReason(reasons, !isDigest(update?.updatedRecordHash), 'training_record_update_hash_invalid');
  addReason(reasons, !isDigest(update?.previousRecordHash), 'training_previous_record_hash_invalid');
  addReason(reasons, hlcTuple(update?.updatedAtHlc) === null, 'training_record_update_time_invalid');
  addReason(reasons, hlcBefore(update?.updatedAtHlc, input?.competenceVerification?.verifiedAtHlc), 'training_record_update_before_competence');
  addReason(reasons, hlcAfter(update?.updatedAtHlc, input?.checkedAtHlc), 'training_record_update_after_check');
  addReason(reasons, update?.metadataOnly !== true, 'training_record_update_metadata_boundary_invalid');
}

function evaluateDelegationEligibilityUpdate(input, reasons) {
  const update = input?.delegationEligibilityUpdate;
  addReason(reasons, update?.controlledActionPermitted !== true, 'delegation_eligibility_not_permitted');
  addReason(reasons, !hasText(update?.eligibilityReceiptId), 'delegation_eligibility_receipt_absent');
  addReason(reasons, !isDigest(update?.eligibilityHash), 'delegation_eligibility_hash_invalid');
  addReason(reasons, !hasText(update?.delegationRef), 'delegation_ref_absent');
  addReason(reasons, hlcTuple(update?.updatedAtHlc) === null, 'delegation_eligibility_update_time_invalid');
  addReason(reasons, hlcBefore(update?.updatedAtHlc, input?.trainingRecordUpdate?.updatedAtHlc), 'delegation_eligibility_before_record_update');
  addReason(reasons, hlcAfter(update?.updatedAtHlc, input?.checkedAtHlc), 'delegation_eligibility_after_check');
  addReason(reasons, update?.metadataOnly !== true, 'delegation_eligibility_metadata_boundary_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, review?.decision !== 'training_gap_closed', 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'human_review_final_authority_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.delegationEligibilityUpdate?.updatedAtHlc), 'human_review_before_delegation_update');
  addReason(reasons, hlcAfter(review?.reviewedAtHlc, input?.checkedAtHlc), 'human_review_after_check');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function collectEvidenceHashes(input) {
  return uniqueSorted([
    input?.gap?.evidenceHash,
    input?.notification?.notificationEvidenceHash,
    input?.assignment?.assignmentEvidenceHash,
    input?.completion?.trainingRecordHash,
    input?.assessment?.assessmentEvidenceHash,
    input?.competenceVerification?.competencyEvidenceHash,
    input?.trainingRecordUpdate?.updatedRecordHash,
    input?.trainingRecordUpdate?.previousRecordHash,
    input?.delegationEligibilityUpdate?.eligibilityHash,
    input?.humanReview?.decisionHash,
    input?.aiAssistance?.recommendationHash,
  ].filter(isDigest));
}

function buildTrainingGap(input, receiptId) {
  const evidenceHashes = collectEvidenceHashes(input);
  const material = {
    actorDid: input.gap.actorDid,
    authorityChainHash: input.authority.authorityChainHash,
    checkedAtHlc: input.checkedAtHlc,
    controlledAction: input.gap.controlledAction,
    evidenceHashes,
    gapId: input.gap.gapId,
    procedureSteps: PROCEDURE_STEPS,
    protocolId: input.protocolId,
    requirementId: input.gap.requirementId,
    role: input.gap.role,
    schema: `${GAP_SCHEMA}_material`,
    siteId: input.siteId,
    status: input.gap.status,
    tenantId: input.tenantId,
  };
  const gapLifecycleHash = sha256Hex(material);

  return {
    schema: GAP_SCHEMA,
    gapManagementId: `cmstg_${gapLifecycleHash.slice(0, 32)}`,
    gapLifecycleHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    protocolId: input.protocolId,
    gapId: input.gap.gapId,
    requirementId: input.gap.requirementId,
    actorDid: input.gap.actorDid,
    role: input.gap.role,
    controlledAction: input.gap.controlledAction,
    status: input.gap.status,
    checkedAtHlc: input.checkedAtHlc,
    procedureSteps: [...PROCEDURE_STEPS],
    evidenceHashes,
    authorityChainHash: input.authority.authorityChainHash,
    receiptId,
  };
}

function buildReceipt(input, gapLifecycleHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'staff_training_gap_management',
    artifactVersion: `${input.protocolId}@${input.gap.gapId}`,
    artifactHash: gapLifecycleHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['competency', 'human_governance', 'metadata_only', 'training_gap'],
    sourceSystem: 'cybermedica-qms',
  });
}

function deniedResponse(reasons) {
  return {
    schema: DECISION_SCHEMA,
    decision: 'denied',
    failClosed: true,
    reasons,
    trainingGap: null,
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateStaffTrainingGapManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];

  evaluateTenantActorAuthority(input, reasons);
  evaluateTrainingMatrix(input?.trainingMatrix, reasons);
  evaluateGap(input ?? {}, reasons);
  evaluateNotification(input ?? {}, reasons);
  evaluateAssignment(input ?? {}, reasons);
  evaluateCompletion(input ?? {}, reasons);
  evaluateAssessment(input ?? {}, reasons);
  evaluateCompetence(input ?? {}, reasons);
  evaluateRecordUpdate(input ?? {}, reasons);
  evaluateDelegationEligibilityUpdate(input ?? {}, reasons);
  evaluateHumanReview(input ?? {}, reasons);

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return deniedResponse(normalizedReasons);
  }

  const materialGap = buildTrainingGap(input, null);
  const receipt = buildReceipt(input, materialGap.gapLifecycleHash);
  const trainingGap = {
    ...materialGap,
    receiptId: receipt.receiptId,
  };

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    trainingGap,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
