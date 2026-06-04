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

const ACTOR_KINDS = new Set(['human', 'service_account']);
const REQUESTER_CLASSES = new Set(['cro', 'sponsor']);
const REQUEST_TYPES = new Set([
  'audit_evidence',
  'corrective_action_status',
  'monitoring_follow_up',
  'readiness_packet',
  'site_feasibility',
]);
const REQUEST_PURPOSES = new Set(['monitoring', 'sponsor_cro_diligence']);
const REQUEST_DOMAIN_SET = new Set([
  'audit_evidence',
  'capa_status',
  'consent_readiness',
  'deviation_status',
  'evidence_index',
  'monitoring_findings',
  'quality_metrics',
  'risk_register',
  'site_readiness',
  'training_status',
]);
const WORK_ITEM_STATUSES = new Set(['queued_for_site_review', 'routed_to_decision_forum']);
const WORK_ITEM_PRIORITIES = new Set(['standard', 'expedited', 'urgent']);
const DECISION_FORUM_STATES = new Set(['routed', 'accepted_for_review']);
const HUMAN_REVIEW_STATUSES = new Set(['approved_for_intake']);

const RAW_REQUEST_FIELDS = new Set([
  'clinicalnarrative',
  'participantlisting',
  'rawcrorequest',
  'rawrequest',
  'rawrequestbody',
  'rawrequestcontent',
  'rawrequestnarrative',
  'rawsponsorrequest',
  'rawsponsorrequestbody',
  'sourcecontent',
  'sourcedocument',
  'sourcedocumentbody',
  'sourcepayload',
]);

const SECRET_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawRequestContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRequestContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_REQUEST_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw sponsor/cro request content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`sponsor/cro request secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRequestContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRequestContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.requesterTenantId), 'requester_tenant_absent');
  addReason(reasons, input?.requesterTenantId === input?.tenantId, 'requester_tenant_not_external');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'request_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'read') || !hasAuthorityPermission(input?.authority, 'request_disclosure'),
    'request_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizeRequest(input, requestedDomains, reasons) {
  const request = input?.request;
  addReason(reasons, !hasText(request?.requestRef), 'request_ref_absent');
  addReason(reasons, !REQUESTER_CLASSES.has(request?.requesterClass), 'requester_class_unsupported');
  addReason(reasons, !REQUEST_TYPES.has(request?.requestType), 'request_type_unsupported');
  addReason(reasons, !REQUEST_PURPOSES.has(request?.purpose), 'request_purpose_unsupported');
  addReason(reasons, requestedDomains.length === 0, 'request_domains_absent');
  addReason(reasons, request?.metadataOnly !== true, 'request_metadata_boundary_invalid');
  addReason(reasons, request?.sourcePayloadExcluded !== true, 'request_source_payload_boundary_invalid');
  addReason(reasons, request?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'request_time_invalid');
  addReason(reasons, hlcTuple(request?.responseDueAtHlc) === null, 'response_due_time_invalid');
  addReason(reasons, !hlcAfter(request?.responseDueAtHlc, request?.requestedAtHlc), 'response_due_not_after_request');

  for (const domain of requestedDomains) {
    addReason(reasons, !REQUEST_DOMAIN_SET.has(domain), `request_domain_unsupported:${domain}`);
  }
}

function evaluateAccessPolicy(input, requestedDomains, reasons) {
  const policy = input?.accessPolicy;
  const allowedClasses = sortedTextList(policy?.allowedRequesterClasses);
  const allowedPurposes = sortedTextList(policy?.allowedPurposes);
  const allowedDomains = sortedTextList(policy?.allowedDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'access_policy_hash_invalid');
  addReason(reasons, !allowedClasses.includes(input?.request?.requesterClass), 'requester_class_not_allowed');
  addReason(reasons, !allowedPurposes.includes(input?.request?.purpose), 'request_purpose_not_allowed');
  addReason(reasons, policy?.siteApprovalRequired !== true, 'site_approval_required_absent');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'disclosure_log_required_absent');
  addReason(reasons, policy?.participantDirectIdentifiersExcluded !== true, 'participant_identifier_boundary_invalid');
  addReason(reasons, policy?.sponsorConfidentialMinimized !== true, 'sponsor_confidential_boundary_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'access_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  for (const domain of requestedDomains) {
    addReason(reasons, !allowedDomains.includes(domain), `request_domain_not_allowed:${domain}`);
  }
}

function normalizeDomainRequests(input, requestedDomains, reasons) {
  const rows = Array.isArray(input?.domainRequests) ? input.domainRequests : [];
  addReason(reasons, rows.length === 0, 'domain_requests_absent');

  const byDomain = new Map();
  for (const row of rows) {
    const domain = hasText(row?.domain) ? row.domain : 'unknown';
    addReason(reasons, byDomain.has(domain), `domain_request_duplicate:${domain}`);
    byDomain.set(domain, row);
  }

  const normalized = requestedDomains.map((domain) => {
    const row = byDomain.get(domain);
    addReason(reasons, row === undefined, `domain_request_missing:${domain}`);
    addReason(reasons, row?.requested !== true, `domain_not_requested:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceIndexHash), `domain_evidence_index_hash_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.disclosureBoundaryHash), `domain_disclosure_boundary_hash_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.accessDecisionHash), `domain_access_decision_hash_invalid:${domain}`);
    addReason(reasons, row?.metadataOnly !== true, `domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `domain_protected_content_boundary_invalid:${domain}`);
    addReason(reasons, row?.sponsorConfidentialMinimized !== true, `domain_sponsor_confidential_boundary_invalid:${domain}`);
    addReason(reasons, row?.sourcePayloadExcluded !== true, `domain_source_payload_boundary_invalid:${domain}`);

    return {
      accessDecisionHash: row?.accessDecisionHash ?? null,
      disclosureBoundaryHash: row?.disclosureBoundaryHash ?? null,
      domain,
      evidenceIndexHash: row?.evidenceIndexHash ?? null,
      metadataOnly: row?.metadataOnly === true,
      protectedContentExcluded: row?.protectedContentExcluded === true,
      requested: row?.requested === true,
      sourcePayloadExcluded: row?.sourcePayloadExcluded === true,
      sponsorConfidentialMinimized: row?.sponsorConfidentialMinimized === true,
    };
  });

  return normalized;
}

function evaluateWorkItem(input, reasons) {
  const workItem = input?.workItem;
  addReason(reasons, !hasText(workItem?.workItemRef), 'work_item_ref_absent');
  addReason(reasons, !hasText(workItem?.ownerRoleRef), 'work_item_owner_absent');
  addReason(reasons, !WORK_ITEM_STATUSES.has(workItem?.status), 'work_item_status_invalid');
  addReason(reasons, !WORK_ITEM_PRIORITIES.has(workItem?.priority), 'work_item_priority_invalid');
  addReason(reasons, !isDigest(workItem?.triageEvidenceHash), 'work_item_triage_hash_invalid');
  addReason(reasons, !hasText(workItem?.responseWorkflowRef), 'work_item_response_workflow_absent');
  addReason(reasons, hlcTuple(workItem?.createdAtHlc) === null, 'work_item_created_time_invalid');
  addReason(reasons, !hlcAfter(workItem?.createdAtHlc, input?.request?.requestedAtHlc), 'work_item_created_not_after_request');
  addReason(reasons, workItem?.metadataOnly !== true, 'work_item_metadata_boundary_invalid');
}

function evaluateDecisionForum(input, reasons) {
  if (input?.request?.materialDecisionImpact !== true) {
    return;
  }
  const forum = input?.decisionForum;
  addReason(reasons, forum?.requiredForMaterialRequest !== true, 'material_request_decision_forum_required_absent');
  addReason(reasons, !hasText(forum?.matterRef), 'material_request_decision_forum_matter_absent');
  addReason(reasons, !isDigest(forum?.routingReceiptHash), 'material_request_decision_forum_receipt_hash_invalid');
  addReason(reasons, !DECISION_FORUM_STATES.has(forum?.state), 'material_request_decision_forum_state_invalid');
  addReason(reasons, forum?.humanGate?.verified !== true, 'material_request_human_gate_unverified');
  addReason(reasons, forum?.openChallenge === true, 'material_request_open_challenge');
  addReason(reasons, forum?.metadataOnly !== true, 'material_request_decision_forum_metadata_boundary_invalid');
}

function evaluateDisclosureEvent(input, reasons) {
  const event = input?.disclosureEvent;
  const disclosureClasses = sortedTextList(event?.disclosureClasses);
  addReason(reasons, !hasText(event?.eventRef), 'disclosure_event_ref_absent');
  addReason(reasons, !isDigest(event?.disclosureLogHash), 'disclosure_event_hash_invalid');
  addReason(reasons, event?.recipientClass !== input?.request?.requesterClass, 'disclosure_recipient_class_mismatch');
  addReason(reasons, event?.purpose !== input?.request?.purpose, 'disclosure_purpose_mismatch');
  addReason(reasons, hlcTuple(event?.loggedAtHlc) === null, 'disclosure_event_time_invalid');
  addReason(reasons, !hlcAfter(event?.loggedAtHlc, input?.request?.requestedAtHlc), 'disclosure_event_not_after_request');
  addReason(reasons, disclosureClasses.length === 0, 'disclosure_classes_absent');
  addReason(reasons, event?.includesRawContent === true, 'disclosure_event_raw_content_included');
  addReason(reasons, event?.metadataOnly !== true, 'disclosure_event_metadata_boundary_invalid');
  addReason(reasons, event?.sourcePayloadExcluded !== true, 'disclosure_event_source_payload_boundary_invalid');
  return disclosureClasses;
}

function evaluateAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined || ai.used !== true) {
    return;
  }
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, sortedTextList(ai.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !isDigest(ai.reasoningSummaryHash), 'ai_reasoning_summary_hash_invalid');
  addReason(reasons, !isBasisPoints(ai.confidenceBasisPoints), 'ai_confidence_invalid');
  addReason(reasons, sortedTextList(ai.recommendedHumanReviewerDids).length === 0, 'ai_recommended_human_reviewer_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_STATUSES.has(review?.status), 'human_review_not_approved');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.request?.requestedAtHlc), 'human_review_not_after_request');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'ai_final_authority_rejection_absent');
}

function buildWorkItem(input, requestedDomains, domainRequests, disclosureClasses) {
  const objectRefs = sortedTextList(input?.request?.objectRefs);
  const requestHash = sha256Hex({
    tenantId: input.tenantId,
    requesterTenantId: input.requesterTenantId,
    requestRef: input.request.requestRef,
    requesterClass: input.request.requesterClass,
    requestType: input.request.requestType,
    purpose: input.request.purpose,
    requestedDomains,
    objectRefs,
    domainRequests,
    disclosureClasses,
    workItemRef: input.workItem.workItemRef,
    decisionForumMatterRef: input.decisionForum?.matterRef ?? null,
    disclosureEventRef: input.disclosureEvent.eventRef,
  });

  return {
    schema: 'cybermedica.sponsor_cro_request_work_item.v1',
    workItemRef: input.workItem.workItemRef,
    requestRef: input.request.requestRef,
    requesterTenantId: input.requesterTenantId,
    requesterClass: input.request.requesterClass,
    requestType: input.request.requestType,
    purpose: input.request.purpose,
    status: input.workItem.status,
    ownerRoleRef: input.workItem.ownerRoleRef,
    priority: input.workItem.priority,
    requestedDomains,
    objectRefs,
    domainCount: requestedDomains.length,
    materialDecisionImpact: input.request.materialDecisionImpact === true,
    decisionForumMatterRef: input.decisionForum?.matterRef ?? null,
    disclosureEventRef: input.disclosureEvent.eventRef,
    responseWorkflowRef: input.workItem.responseWorkflowRef,
    responseDueAtHlc: input.request.responseDueAtHlc,
    requestHash,
    metadataOnly: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, workItem) {
  const artifactHash = sha256Hex({
    workItem,
    disclosureLogHash: input.disclosureEvent.disclosureLogHash,
    triageEvidenceHash: input.workItem.triageEvidenceHash,
    reviewEvidenceHash: input.humanReview.reviewEvidenceHash,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'sponsor_cro_request_work_item',
    artifactVersion: `${input.request.requestRef}@${input.request.requestedAtHlc.physicalMs}.${input.request.requestedAtHlc.logical}`,
    artifactHash,
    classification: 'sponsor_cro_request_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['sponsor_cro_request', 'disclosure_metadata', 'metadata_only'],
    sourceSystem: 'cybermedica.sponsor_cro_request_management',
  });
}

export function evaluateSponsorCroRequest(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const requestedDomains = sortedTextList(input?.request?.requestedDomains);

  evaluateTenantActorAuthority(input, reasons);
  normalizeRequest(input, requestedDomains, reasons);
  evaluateAccessPolicy(input, requestedDomains, reasons);
  const domainRequests = normalizeDomainRequests(input, requestedDomains, reasons);
  evaluateWorkItem(input, reasons);
  evaluateDecisionForum(input, reasons);
  const disclosureClasses = evaluateDisclosureEvent(input, reasons);
  evaluateAiAssistance(input, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.sponsor_cro_request_management.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      workItem: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const workItem = buildWorkItem(input, requestedDomains, domainRequests, disclosureClasses);
  return {
    schema: 'cybermedica.sponsor_cro_request_management.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    workItem,
    disclosureEvent: {
      eventRef: input.disclosureEvent.eventRef,
      disclosureLogHash: input.disclosureEvent.disclosureLogHash,
      disclosureClasses,
      metadataOnly: true,
      sourcePayloadExcluded: true,
    },
    receipt: buildReceipt(input, workItem),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
