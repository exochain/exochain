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

const EVENT_CLASSIFICATIONS = new Set(['ae', 'sae', 'susar', 'protocol_defined_safety_event']);
const EXPECTEDNESS_VALUES = new Set(['expected', 'unexpected', 'unknown']);
const RELATEDNESS_VALUES = new Set(['definite', 'probable', 'possible', 'unlikely', 'not_related', 'unknown']);
const SUSPECTED_RELATEDNESS = new Set(['definite', 'probable', 'possible']);
const SEVERITY_VALUES = new Set(['mild', 'moderate', 'severe', 'life_threatening', 'fatal']);
const CRITICAL_SEVERITIES = new Set(['severe', 'life_threatening', 'fatal']);
const CLOSURE_STATUSES = new Set(['closure_ready', 'closed']);
const EVENT_STATUSES = new Set(['reported', 'follow_up_open', 'investigation_open', 'closure_ready', 'closed']);
const RAW_SAFETY_FIELDS = new Set([
  'adverseeventnarrative',
  'autopsyreportbody',
  'eventdetailsbody',
  'eventnarrative',
  'labreportbody',
  'medicalreportbody',
  'participantidentifier',
  'participantuniquecode',
  'raweventdetails',
  'rawlabreport',
  'rawmedicalreport',
  'rawparticipantcode',
  'rawsafetyevent',
  'subjectidentifier',
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

function assertNoRawSafetyText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSafetyText(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_SAFETY_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw safety event content field is not allowed at ${path}.${key}`);
    }
    assertNoRawSafetyText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSafetyText(input ?? {});
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
    !hasAuthorityPermission(input?.authority, 'manage_safety_events') && !hasAuthorityPermission(input?.authority, 'write'),
    'safety_event_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function criticalEscalationRequired(event) {
  return (
    event?.classification === 'susar' ||
    event?.classification === 'sae' ||
    event?.serious === true ||
    CRITICAL_SEVERITIES.has(event?.severity)
  );
}

function eventDrivenCapaRequired(event) {
  return (
    event?.classification === 'susar' ||
    (event?.serious === true && SUSPECTED_RELATEDNESS.has(event?.relatedness)) ||
    event?.severity === 'life_threatening' ||
    event?.severity === 'fatal'
  );
}

function clinicalResponseRequired(input) {
  return input?.clinicalResponse?.required === true || criticalEscalationRequired(input?.safetyEvent);
}

function investigationRequired(input) {
  return input?.investigation?.required === true || criticalEscalationRequired(input?.safetyEvent);
}

function followUpRequired(input) {
  return input?.followUp?.required === true || criticalEscalationRequired(input?.safetyEvent);
}

function closureRequested(event) {
  return CLOSURE_STATUSES.has(event?.status);
}

function evaluateSafetyEventShape(event, reasons) {
  addReason(reasons, !hasText(event?.eventRef), 'safety_event_ref_absent');
  addReason(reasons, !hasText(event?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(event?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(event?.siteRef), 'site_ref_absent');
  addReason(reasons, !isDigest(event?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(event?.participantCodeScope), 'participant_code_scope_absent');
  addReason(reasons, !EVENT_CLASSIFICATIONS.has(event?.classification), 'safety_event_classification_invalid');
  addReason(reasons, typeof event?.serious !== 'boolean', 'serious_flag_invalid');
  addReason(reasons, !EXPECTEDNESS_VALUES.has(event?.expectedness), 'expectedness_invalid');
  addReason(reasons, !RELATEDNESS_VALUES.has(event?.relatedness), 'relatedness_invalid');
  addReason(reasons, !SEVERITY_VALUES.has(event?.severity), 'severity_invalid');
  addReason(reasons, hlcTuple(event?.onsetAtHlc) === null, 'onset_time_invalid');
  addReason(
    reasons,
    event?.resolutionAtHlc !== null && event?.resolutionAtHlc !== undefined && !hlcAfterOrEqual(event.resolutionAtHlc, event.onsetAtHlc),
    'resolution_time_precedes_onset',
  );
  addReason(reasons, !isDigest(event?.eventDetailsHash), 'event_details_hash_invalid');
  addReason(reasons, !isDigest(event?.investigatorAssessmentHash), 'investigator_assessment_hash_invalid');
  addReason(reasons, !EVENT_STATUSES.has(event?.status), 'safety_event_status_invalid');
  addReason(reasons, sortedTextList(event?.policyRefs).length === 0, 'policy_refs_absent');

  const reportHashes = Array.isArray(event?.reportEvidenceHashes) ? event.reportEvidenceHashes : [];
  addReason(reasons, reportHashes.some((hash) => !isDigest(hash)), 'safety_report_evidence_hash_invalid');
  addReason(reasons, criticalEscalationRequired(event) && reportHashes.filter(isDigest).length === 0, 'safety_report_evidence_absent');
  addReason(reasons, event?.classification === 'susar' && event?.serious !== true, 'susar_criteria_incomplete');
  addReason(reasons, event?.classification === 'susar' && event?.expectedness !== 'unexpected', 'susar_criteria_incomplete');
  addReason(reasons, event?.classification === 'susar' && !SUSPECTED_RELATEDNESS.has(event?.relatedness), 'susar_criteria_incomplete');
  addReason(reasons, event?.classification === 'sae' && event?.serious !== true, 'sae_criteria_incomplete');
  addReason(
    reasons,
    event?.serious === true && event?.classification === 'ae',
    'serious_event_requires_sae_or_susar_classification',
  );
}

function evaluateClinicalResponse(input, reasons) {
  const required = clinicalResponseRequired(input);
  const response = input?.clinicalResponse;
  addReason(reasons, typeof response?.required !== 'boolean', 'clinical_response_requirement_invalid');

  if (required) {
    const incomplete =
      response?.status !== 'completed' ||
      !isDigest(response?.responseEvidenceHash) ||
      hlcTuple(response?.initiatedAtHlc) === null ||
      hlcTuple(response?.completedAtHlc) === null ||
      !hlcAfterOrEqual(response?.completedAtHlc, response?.initiatedAtHlc) ||
      !hlcAfterOrEqual(response?.initiatedAtHlc, input?.safetyEvent?.onsetAtHlc) ||
      !hasText(response?.responsibleClinicianDid);
    addReason(reasons, incomplete, 'clinical_response_evidence_absent');
    return incomplete ? 'incomplete' : 'complete';
  }

  const invalid = response?.status !== 'not_required' || !isDigest(response?.rationaleHash);
  addReason(reasons, invalid, 'clinical_response_rationale_absent');
  return invalid ? 'incomplete' : 'not_required';
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
  const requiredParties = ['sponsor', 'irb', 'regulatory'];
  const incomplete = [];
  for (const party of requiredParties) {
    if (!reportingDecisionComplete(reporting?.[party])) {
      reasons.push(`${party}_reporting_incomplete`);
      incomplete.push(party);
    }
  }
  return incomplete.length === 0 ? 'complete' : 'incomplete';
}

function requiredNotificationParties(event) {
  const parties = ['principal_investigator'];
  if (criticalEscalationRequired(event)) {
    parties.push('decision_forum', 'site_quality_lead', 'sponsor_safety_contact');
  }
  return uniqueSorted(parties);
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
  for (const party of requiredNotificationParties(input?.safetyEvent).filter((value) => value !== 'decision_forum')) {
    if (!notificationComplete(byParty.get(party))) {
      reasons.push(`${party}_notification_incomplete`);
      incomplete.push(party);
    }
  }
  return incomplete.length === 0 ? 'complete' : 'incomplete';
}

function evaluateInvestigation(input, reasons) {
  const required = investigationRequired(input);
  const investigation = input?.investigation;
  addReason(reasons, typeof investigation?.required !== 'boolean', 'investigation_requirement_invalid');

  if (required) {
    const baseIncomplete =
      !['open', 'complete'].includes(investigation?.status) ||
      !hasText(investigation?.investigatorDid) ||
      !isDigest(investigation?.planHash) ||
      hlcTuple(investigation?.openedAtHlc) === null;
    addReason(reasons, baseIncomplete, 'investigation_evidence_absent');
    const closureIncomplete =
      closureRequested(input?.safetyEvent) &&
      (investigation?.status !== 'complete' ||
        !isDigest(investigation?.findingsHash) ||
        hlcTuple(investigation?.completedAtHlc) === null ||
        !hlcAfterOrEqual(investigation?.completedAtHlc, investigation?.openedAtHlc));
    addReason(reasons, closureIncomplete, 'investigation_incomplete');
    return closureIncomplete || baseIncomplete ? 'incomplete' : investigation.status;
  }

  const invalid = investigation?.status !== 'not_required' || !isDigest(investigation?.rationaleHash);
  addReason(reasons, invalid, 'investigation_rationale_absent');
  return invalid ? 'incomplete' : 'not_required';
}

function evaluateFollowUp(input, reasons) {
  const required = followUpRequired(input);
  const followUp = input?.followUp;
  addReason(reasons, typeof followUp?.required !== 'boolean', 'follow_up_requirement_invalid');

  if (required) {
    const reportHashes = Array.isArray(followUp?.reportHashes) ? followUp.reportHashes : [];
    const countsInvalid =
      !Number.isSafeInteger(followUp?.requiredReportCount) ||
      !Number.isSafeInteger(followUp?.completedReportCount) ||
      followUp.requiredReportCount < 1 ||
      followUp.completedReportCount < 0 ||
      followUp.completedReportCount > followUp.requiredReportCount;
    const baseIncomplete =
      !['pending', 'complete'].includes(followUp?.status) ||
      countsInvalid ||
      reportHashes.length !== followUp?.completedReportCount ||
      reportHashes.some((hash) => !isDigest(hash));
    addReason(reasons, baseIncomplete, 'follow_up_evidence_invalid');
    addReason(reasons, followUp?.status === 'pending' && hlcTuple(followUp?.nextDueAtHlc) === null, 'follow_up_next_due_invalid');
    const closureIncomplete =
      closureRequested(input?.safetyEvent) &&
      (followUp?.status !== 'complete' ||
        followUp.completedReportCount !== followUp.requiredReportCount ||
        hlcTuple(followUp?.completedAtHlc) === null);
    addReason(reasons, closureIncomplete, 'follow_up_incomplete');
    return closureIncomplete || baseIncomplete ? 'incomplete' : followUp.status;
  }

  const invalid = followUp?.status !== 'not_required' || !isDigest(followUp?.rationaleHash);
  addReason(reasons, invalid, 'follow_up_rationale_absent');
  return invalid ? 'incomplete' : 'not_required';
}

function evaluateLinkage(linkage, required, prefix, reasons) {
  addReason(reasons, typeof linkage?.required !== 'boolean', `${prefix}_requirement_invalid`);
  if (!required) {
    return 'not_required';
  }
  const absent = !hasText(linkage?.[`${prefix}Ref`]) || !hasText(linkage?.receiptId);
  addReason(reasons, absent, `${prefix}_linkage_absent`);
  return absent ? 'incomplete' : 'linked';
}

function evaluateDecisionForum(decisionForum, required, reasons) {
  if (!required) {
    return 'not_required';
  }
  const invalid =
    decisionForum?.linkageRequired !== true ||
    decisionForum?.verified !== true ||
    decisionForum?.state !== 'approved' ||
    decisionForum?.humanGate?.verified !== true ||
    decisionForum?.quorum?.status !== 'met' ||
    decisionForum?.openChallenge === true ||
    !hasText(decisionForum?.decisionId) ||
    !hasText(decisionForum?.workflowReceiptId);
  addReason(reasons, invalid, 'critical_escalation_route_absent');
  return invalid ? 'incomplete' : 'required_ready';
}

function evaluateClosureReview(input, reasons) {
  if (!closureRequested(input?.safetyEvent)) {
    return 'not_requested';
  }
  const closureReview = input?.closureReview;
  const forum = closureReview?.decisionForum;
  const invalid =
    !hasText(closureReview?.closedByDid) ||
    !isDigest(closureReview?.closureEvidenceHash) ||
    hlcTuple(closureReview?.closedAtHlc) === null ||
    !hlcAfterOrEqual(closureReview?.closedAtHlc, input?.safetyEvent?.onsetAtHlc) ||
    forum?.verified !== true ||
    forum?.state !== 'approved' ||
    forum?.humanGate?.verified !== true ||
    forum?.quorum?.status !== 'met' ||
    forum?.openChallenge === true ||
    !hasText(forum?.decisionId) ||
    !hasText(forum?.workflowReceiptId);
  addReason(reasons, invalid, 'closure_human_governance_absent');
  return invalid ? 'incomplete' : 'complete';
}

function safetyEventId(input) {
  return `cmse_${sha256Hex({
    eventRef: input?.safetyEvent?.eventRef ?? null,
    participantCodeHash: input?.safetyEvent?.participantCodeHash ?? null,
    protocolRef: input?.safetyEvent?.protocolRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function createSafetyReceipt(input, artifactType, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType,
    artifactVersion: input.safetyEvent.status,
    classification: 'safety_event_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.safetyEvent.onsetAtHlc,
    sensitivityTags: ['metadata_only', 'participant_code_hash', 'safety_event'],
    sourceSystem: 'cybermedica.safety_events',
    tenantId: input.tenantId,
  });
}

function buildEventSummary(input, statuses) {
  const event = input?.safetyEvent ?? {};
  const immediateEscalation = criticalEscalationRequired(event);
  const capaRequired = input?.capaLinkage?.required === true || eventDrivenCapaRequired(event);
  return {
    schema: 'cybermedica.safety_event_summary.v1',
    safetyEventId: safetyEventId(input),
    eventRef: event.eventRef ?? null,
    classification: event.classification ?? null,
    serious: event.serious === true,
    severity: event.severity ?? null,
    relatedness: event.relatedness ?? null,
    expectedness: event.expectedness ?? null,
    immediateEscalationRequired: immediateEscalation,
    requiredEscalationRoles: requiredNotificationParties(event),
    escalationStatus: statuses.escalationStatus,
    clinicalResponseStatus: statuses.clinicalResponseStatus,
    reportingStatus: statuses.reportingStatus,
    notificationStatus: statuses.notificationStatus,
    investigationStatus: statuses.investigationStatus,
    followUpStatus: statuses.followUpStatus,
    deviationLinkageStatus: statuses.deviationLinkageStatus,
    capaRequired,
    capaLinkageStatus: statuses.capaLinkageStatus,
    closureStatus: statuses.closureStatus,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

export function evaluateSafetyEventWorkflow(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateSafetyEventShape(input?.safetyEvent, reasons);

  const clinicalResponseStatus = evaluateClinicalResponse(input, reasons);
  const reportingStatus = evaluateReporting(input?.reporting, reasons);
  const notificationStatus = evaluateNotifications(input, reasons);
  const investigationStatus = evaluateInvestigation(input, reasons);
  const followUpStatus = evaluateFollowUp(input, reasons);
  const escalationRequired = criticalEscalationRequired(input?.safetyEvent);
  const escalationStatus = evaluateDecisionForum(input?.decisionForum, escalationRequired, reasons);
  const deviationLinkageStatus = evaluateLinkage(input?.deviationLinkage, input?.deviationLinkage?.required === true, 'deviation', reasons);
  const capaRequired = input?.capaLinkage?.required === true || eventDrivenCapaRequired(input?.safetyEvent);
  const capaLinkageStatus = evaluateLinkage(input?.capaLinkage, capaRequired, 'capa', reasons);
  const closureReviewStatus = evaluateClosureReview(input, reasons);
  const closureStatus = closureRequested(input?.safetyEvent) && closureReviewStatus === 'complete' ? 'closed' : 'open';

  const statuses = {
    capaLinkageStatus,
    clinicalResponseStatus,
    closureStatus,
    deviationLinkageStatus,
    escalationStatus,
    followUpStatus,
    investigationStatus,
    notificationStatus,
    reportingStatus,
  };
  const safetyEvent = buildEventSummary(input, statuses);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.safety_event_workflow.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      safetyEvent,
      receipt: null,
      closureReceipt: null,
    };
  }

  const recordHash = sha256Hex({
    actorDid: input.actor.did,
    capaLinkageStatus,
    clinicalResponseStatus,
    decisionForumReceipt: input.decisionForum?.workflowReceiptId ?? null,
    eventDetailsHash: input.safetyEvent.eventDetailsHash,
    eventRef: input.safetyEvent.eventRef,
    followUpStatus,
    investigationStatus,
    notificationParties: requiredNotificationParties(input.safetyEvent),
    participantCodeHash: input.safetyEvent.participantCodeHash,
    policyRefs: sortedTextList(input.safetyEvent.policyRefs),
    reportEvidenceHashes: sortedTextList(input.safetyEvent.reportEvidenceHashes),
    reportingStatus,
    safetyEventId: safetyEvent.safetyEventId,
    tenantId: input.tenantId,
  });
  const receipt = createSafetyReceipt(input, 'safety_event_record', recordHash);
  const closureReceipt =
    closureStatus === 'closed'
      ? createSafetyReceipt(
          input,
          'safety_event_closure',
          sha256Hex({
            closedAtHlc: input.closureReview.closedAtHlc,
            closedByDid: input.closureReview.closedByDid,
            closureEvidenceHash: input.closureReview.closureEvidenceHash,
            decisionForumReceipt: input.closureReview.decisionForum.workflowReceiptId,
            safetyEventId: safetyEvent.safetyEventId,
            tenantId: input.tenantId,
          }),
        )
      : null;

  return {
    schema: 'cybermedica.safety_event_workflow.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    safetyEvent,
    receipt,
    closureReceipt,
  };
}
