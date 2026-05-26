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
const ACTION_TYPES = new Set([
  'consent_exception',
  'data_integrity',
  'facility_failure',
  'participant_safety',
  'product_handling',
  'unauthorized_access',
]);
const TRIGGER_DOMAINS = new Set([
  'consent',
  'data_integrity',
  'ethics',
  'facility',
  'participant_safety',
  'product_handling',
  'security',
]);
const SEVERITIES = new Set(['urgent', 'critical']);
const REVIEW_STATUSES = new Set(['pending', 'complete']);
const REVIEW_OUTCOMES = new Set(['escalate', 'ratify', 'ratify_with_conditions', 'revoke']);
const RAW_EMERGENCY_FIELDS = new Set([
  'actionnarrative',
  'clinicalnotes',
  'emergencydetailsbody',
  'justificationtext',
  'participantidentifier',
  'participantuniquecode',
  'rawaction',
  'rawactionnarrative',
  'rawclinicalnote',
  'rawemergencyaction',
  'rawparticipantcode',
  'rawreviewrationale',
  'reviewrationaletext',
  'sourcetext',
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
  return Array.isArray(value) ? uniqueSorted(value.filter(hasText)) : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawEmergencyContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawEmergencyContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_EMERGENCY_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw emergency action content field is not allowed at ${path}.${key}`);
    }
    assertNoRawEmergencyContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawEmergencyContent(input ?? {});
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

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'emergency_action') && !hasAuthorityPermission(input?.authority, 'write'),
    'emergency_action_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function emergencyActionRequiredRoles(action) {
  const roles = ['decision_forum', 'principal_investigator', 'site_quality_lead'];
  if (
    action?.severity === 'critical' ||
    action?.triggerDomain === 'participant_safety' ||
    action?.actionType === 'participant_safety' ||
    action?.actionType === 'product_handling'
  ) {
    roles.push('sponsor_safety_contact');
  }
  return uniqueSorted(roles);
}

function evaluateEmergencyActionShape(action, reasons) {
  addReason(reasons, !hasText(action?.actionRef), 'emergency_action_ref_absent');
  addReason(reasons, !hasText(action?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(action?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(action?.siteRef), 'site_ref_absent');
  addReason(reasons, !isDigest(action?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(action?.participantCodeScope), 'participant_code_scope_absent');
  addReason(reasons, !ACTION_TYPES.has(action?.actionType), 'emergency_action_type_invalid');
  addReason(reasons, !TRIGGER_DOMAINS.has(action?.triggerDomain), 'emergency_trigger_domain_invalid');
  addReason(reasons, !SEVERITIES.has(action?.severity), 'emergency_severity_invalid');
  addReason(reasons, action?.priorApprovalImpracticable !== true, 'prior_approval_impracticable_required');
  addReason(reasons, action?.harmPreventionRequired !== true, 'harm_prevention_required');
  addReason(reasons, !isDigest(action?.actionEvidenceHash), 'emergency_action_evidence_hash_invalid');
  addReason(reasons, !isDigest(action?.justificationHash), 'emergency_justification_hash_invalid');
  addReason(reasons, !isDigest(action?.noPriorApprovalRationaleHash), 'no_prior_approval_rationale_hash_invalid');
  addReason(reasons, !isDigest(action?.scopeHash), 'emergency_scope_hash_invalid');
  addReason(reasons, sortedTextList(action?.policyRefs).length === 0, 'policy_refs_absent');
  addReason(reasons, !['review_pending', 'retrospective_reviewed'].includes(action?.status), 'emergency_action_status_invalid');

  addReason(reasons, hlcTuple(action?.actionStartedAtHlc) === null, 'action_start_time_invalid');
  addReason(reasons, hlcTuple(action?.actionCompletedAtHlc) === null, 'action_completion_time_invalid');
  addReason(reasons, hlcTuple(action?.recordedAtHlc) === null, 'record_time_invalid');
  addReason(reasons, !hlcAfterOrEqual(action?.actionCompletedAtHlc, action?.actionStartedAtHlc), 'action_completion_before_start');
  addReason(reasons, !hlcAfterOrEqual(action?.recordedAtHlc, action?.actionCompletedAtHlc), 'record_before_action_completion');
}

function evaluateClinicalOversight(oversight, reasons) {
  const incomplete =
    !hasText(oversight?.responsibleClinicianDid) ||
    !hasText(oversight?.siteQualityLeadDid) ||
    !isDigest(oversight?.safetyAssessmentHash) ||
    oversight?.participantSafetyProtected !== true;
  addReason(reasons, incomplete, 'clinical_oversight_absent');
}

function reportingDecisionComplete(decision) {
  if (decision?.required === true) {
    return (
      hasText(decision.timelineRef) &&
      decision.status === 'submitted' &&
      isDigest(decision.evidenceHash) &&
      hlcTuple(decision.dueAtHlc) !== null &&
      hlcTuple(decision.submittedAtHlc) !== null &&
      hlcAfterOrEqual(decision.dueAtHlc, decision.submittedAtHlc)
    );
  }
  if (decision?.required === false) {
    return decision.status === 'not_required' && isDigest(decision.rationaleHash);
  }
  return false;
}

function evaluateReporting(reporting, reasons) {
  const requiredParties = ['sponsor', 'irbIec', 'regulatory'];
  const incomplete = [];
  for (const party of requiredParties) {
    if (!reportingDecisionComplete(reporting?.[party])) {
      const reason = `${party === 'irbIec' ? 'irb_iec' : party}_reporting_incomplete`;
      reasons.push(reason);
      incomplete.push(party);
    }
  }
  return incomplete.length === 0 ? 'complete' : 'incomplete';
}

function notificationComplete(notification) {
  return (
    notification?.required === true &&
    notification?.status === 'notified' &&
    isDigest(notification?.evidenceHash) &&
    hlcTuple(notification?.notifiedAtHlc) !== null
  );
}

function evaluateNotifications(input, reasons) {
  const notifications = Array.isArray(input?.notifications) ? input.notifications : [];
  const byParty = new Map();
  for (const notification of notifications) {
    if (hasText(notification?.party)) {
      byParty.set(notification.party, notification);
    }
  }

  const incomplete = [];
  for (const party of emergencyActionRequiredRoles(input?.emergencyAction).filter((value) => value !== 'decision_forum')) {
    if (!notificationComplete(byParty.get(party))) {
      reasons.push(`${party}_notification_incomplete`);
      incomplete.push(party);
    }
  }
  return incomplete.length === 0 ? 'complete' : 'incomplete';
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === null || ai === undefined || ai?.used === false) {
    return 'not_used';
  }
  addReason(reasons, ai?.advisoryOnly !== true, 'ai_assistance_must_be_advisory');
  addReason(reasons, ai?.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, !isDigest(ai?.promptHash), 'ai_assistance_prompt_hash_invalid');
  addReason(reasons, !isDigest(ai?.outputHash), 'ai_assistance_output_hash_invalid');
  const evidenceHashes = Array.isArray(ai?.evidenceUsedHashes) ? ai.evidenceUsedHashes : [];
  addReason(reasons, evidenceHashes.length === 0, 'ai_assistance_evidence_absent');
  addReason(reasons, evidenceHashes.some((hash) => !isDigest(hash)), 'ai_assistance_evidence_hash_invalid');
  addReason(reasons, !hasText(ai?.recommendedHumanReviewerRole), 'ai_assistance_reviewer_role_absent');
  return 'advisory';
}

function followUpActionComplete(action) {
  return hasText(action?.actionRef) && hasText(action?.ownerDid) && hlcTuple(action?.dueAtHlc) !== null && isDigest(action?.evidenceHash);
}

function evaluateRetrospectiveReview(input, reasons) {
  const review = input?.retrospectiveReview;
  addReason(reasons, review?.required !== true, 'retrospective_review_required');
  addReason(reasons, !REVIEW_STATUSES.has(review?.status), 'retrospective_review_status_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'retrospective_review_evidence_bundle_hash_invalid');
  addReason(reasons, hlcTuple(review?.dueAtHlc) === null, 'retrospective_review_due_time_invalid');
  addReason(reasons, !hlcAfterOrEqual(review?.dueAtHlc, input?.emergencyAction?.recordedAtHlc), 'retrospective_review_due_before_record');

  if (review?.status !== 'complete') {
    return 'required_pending';
  }

  const forum = review?.decisionForum;
  const governanceAbsent =
    forum?.verified !== true ||
    forum?.state !== 'approved' ||
    forum?.humanGate?.verified !== true ||
    forum?.quorum?.status !== 'met' ||
    forum?.openChallenge === true ||
    !hasText(forum?.decisionId) ||
    !hasText(forum?.workflowReceiptId);
  addReason(reasons, governanceAbsent, 'retrospective_review_governance_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'retrospective_reviewer_absent');
  addReason(reasons, !REVIEW_OUTCOMES.has(review?.outcome), 'retrospective_review_outcome_invalid');
  addReason(reasons, !isDigest(review?.rationaleHash), 'retrospective_review_rationale_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'retrospective_review_time_invalid');
  addReason(reasons, !hlcAfterOrEqual(review?.reviewedAtHlc, input?.emergencyAction?.recordedAtHlc), 'retrospective_review_before_record');

  const conditionHashes = Array.isArray(review?.conditionHashes) ? review.conditionHashes : [];
  addReason(
    reasons,
    review?.outcome === 'ratify_with_conditions' && conditionHashes.filter(isDigest).length === 0,
    'retrospective_review_conditions_absent',
  );
  addReason(reasons, conditionHashes.some((hash) => !isDigest(hash)), 'retrospective_review_condition_hash_invalid');

  const followUpActions = Array.isArray(review?.followUpActions) ? review.followUpActions : [];
  addReason(
    reasons,
    review?.outcome === 'ratify_with_conditions' && followUpActions.length === 0,
    'retrospective_review_follow_up_absent',
  );
  addReason(reasons, followUpActions.some((action) => !followUpActionComplete(action)), 'retrospective_review_follow_up_invalid');
  addReason(reasons, review?.outcome === 'revoke' && !isDigest(review?.revocationEvidenceHash), 'revocation_evidence_absent');
  return 'complete';
}

function emergencyActionId(input) {
  return `cmea_${sha256Hex({
    actionRef: input?.emergencyAction?.actionRef ?? null,
    participantCodeHash: input?.emergencyAction?.participantCodeHash ?? null,
    protocolRef: input?.emergencyAction?.protocolRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function createEmergencyReceipt(input, artifactType, artifactHash, hlcTimestamp) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType,
    artifactVersion: input.emergencyAction.status,
    classification: 'emergency_action_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp,
    sensitivityTags: ['emergency_action', 'metadata_only', 'participant_code_hash'],
    sourceSystem: 'cybermedica.emergency_actions',
    tenantId: input.tenantId,
  });
}

function buildEmergencyActionSummary(input, statuses) {
  const action = input?.emergencyAction ?? {};
  const review = input?.retrospectiveReview ?? {};
  return {
    schema: 'cybermedica.emergency_action_summary.v1',
    emergencyActionId: emergencyActionId(input),
    actionRef: action.actionRef ?? null,
    actionType: action.actionType ?? null,
    triggerDomain: action.triggerDomain ?? null,
    severity: action.severity ?? null,
    reviewRequired: true,
    requiredEscalationRoles: emergencyActionRequiredRoles(action),
    reportingStatus: statuses.reportingStatus,
    notificationStatus: statuses.notificationStatus,
    aiAssistanceStatus: statuses.aiAssistanceStatus,
    retrospectiveReviewStatus: statuses.retrospectiveReviewStatus,
    reviewOutcome: review.outcome ?? null,
    conditionHashes: sortedTextList(review.conditionHashes),
    followUpActionCount: Array.isArray(review.followUpActions) ? review.followUpActions.length : 0,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

export function evaluateEmergencyActionWorkflow(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateEmergencyActionShape(input?.emergencyAction, reasons);
  evaluateClinicalOversight(input?.clinicalOversight, reasons);

  const reportingStatus = evaluateReporting(input?.reporting, reasons);
  const notificationStatus = evaluateNotifications(input, reasons);
  const aiAssistanceStatus = evaluateAiAssistance(input?.aiAssistance, reasons);
  const retrospectiveReviewStatus = evaluateRetrospectiveReview(input, reasons);
  const statuses = {
    aiAssistanceStatus,
    notificationStatus,
    reportingStatus,
    retrospectiveReviewStatus,
  };
  const emergencyAction = buildEmergencyActionSummary(input, statuses);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.emergency_action_workflow.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      emergencyAction,
      receipt: null,
      reviewReceipt: null,
    };
  }

  const recordHash = sha256Hex({
    actionEvidenceHash: input.emergencyAction.actionEvidenceHash,
    actionRef: input.emergencyAction.actionRef,
    actionType: input.emergencyAction.actionType,
    aiAssistanceStatus,
    emergencyActionId: emergencyAction.emergencyActionId,
    justificationHash: input.emergencyAction.justificationHash,
    notificationParties: emergencyAction.requiredEscalationRoles,
    participantCodeHash: input.emergencyAction.participantCodeHash,
    policyRefs: sortedTextList(input.emergencyAction.policyRefs),
    reportingStatus,
    retrospectiveReviewStatus,
    tenantId: input.tenantId,
  });
  const receipt = createEmergencyReceipt(input, 'emergency_action_record', recordHash, input.emergencyAction.recordedAtHlc);
  const reviewReceipt =
    retrospectiveReviewStatus === 'complete'
      ? createEmergencyReceipt(
          input,
          'emergency_action_retrospective_review',
          sha256Hex({
            conditionHashes: sortedTextList(input.retrospectiveReview.conditionHashes),
            decisionForumReceipt: input.retrospectiveReview.decisionForum.workflowReceiptId,
            emergencyActionId: emergencyAction.emergencyActionId,
            followUpActions: input.retrospectiveReview.followUpActions ?? [],
            outcome: input.retrospectiveReview.outcome,
            rationaleHash: input.retrospectiveReview.rationaleHash,
            reviewedAtHlc: input.retrospectiveReview.reviewedAtHlc,
            reviewerDid: input.retrospectiveReview.reviewerDid,
            tenantId: input.tenantId,
          }),
          input.retrospectiveReview.reviewedAtHlc,
        )
      : null;

  return {
    schema: 'cybermedica.emergency_action_workflow.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    emergencyAction,
    receipt,
    reviewReceipt,
  };
}
