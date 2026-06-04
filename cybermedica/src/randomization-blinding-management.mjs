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
const REQUIRED_PERMISSION = 'manage_randomization_blinding';
const RANDOMIZATION_BLINDING_SCHEMA = 'cybermedica.randomization_blinding_management.v1';

const REQUIRED_RANDOMIZATION_DOMAINS = Object.freeze([
  'allocation_concealment',
  'assignment_code_list',
  'blinding_role_separation',
  'emergency_unblinding_control',
  'participant_identifier_suppression',
  'product_linkage',
  'protocol_version_alignment',
  'randomization_system_validation',
  'sponsor_ethics_notification',
]);

const ACTIVE_PLAN_STATUSES = new Set(['active']);
const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const REVIEW_DECISIONS = new Set(['randomization_blinding_ready', 'hold_randomization_blinding_gap']);

const RAW_RANDOMIZATION_BLINDING_FIELDS = new Set([
  'codebreaknote',
  'directidentifier',
  'participantidentifier',
  'participantname',
  'patientname',
  'randomizationlistbody',
  'randomizationnarrative',
  'rawassignment',
  'rawblindingrecord',
  'rawcodebreak',
  'rawpayload',
  'rawrandomization',
  'rawrandomizationlist',
  'rawrandomizationlistbody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
  'unblindingnote',
]);

const SECRET_RANDOMIZATION_BLINDING_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'codelistsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'randomizationsecret',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function assertNoRawRandomizationBlindingContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRandomizationBlindingContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RANDOMIZATION_BLINDING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw randomization or blinding field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RANDOMIZATION_BLINDING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`randomization or blinding secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRandomizationBlindingContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRandomizationBlindingContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'manage_product_accountability') &&
      !hasAuthorityPermission(input?.authority, 'govern'),
    'randomization_blinding_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredDomains(input, reasons) {
  const requiredDomains = sortedTextList(input?.randomizationPlan?.requiredDomains);
  for (const domainRef of REQUIRED_RANDOMIZATION_DOMAINS) {
    addReason(reasons, !requiredDomains.includes(domainRef), `required_domain_missing:${domainRef}`);
  }
  for (const domainRef of requiredDomains) {
    addReason(reasons, !REQUIRED_RANDOMIZATION_DOMAINS.includes(domainRef), `required_domain_unsupported:${domainRef}`);
  }

  const coveredDomains = sortedTextList(
    (Array.isArray(input?.blindingControls?.domainEvidence) ? input.blindingControls.domainEvidence : [])
      .filter((entry) => VERIFIED_DOMAIN_STATUSES.has(entry?.status) && isDigest(entry?.evidenceHash))
      .map((entry) => entry.domainRef),
  );
  for (const domainRef of REQUIRED_RANDOMIZATION_DOMAINS) {
    addReason(reasons, !coveredDomains.includes(domainRef), `domain_evidence_missing:${domainRef}`);
  }
  return { coveredDomains, requiredDomains };
}

function evaluateRandomizationPlan(input, reasons) {
  const plan = input?.randomizationPlan;
  addReason(reasons, !hasText(plan?.planRef), 'plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.protocolVersionRef), 'protocol_version_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !ACTIVE_PLAN_STATUSES.has(plan?.status), 'plan_not_active');
  addReason(reasons, !isDigest(plan?.randomizationMethodHash), 'randomization_method_hash_invalid');
  addReason(reasons, !isDigest(plan?.allocationRatioHash), 'allocation_ratio_hash_invalid');
  addReason(reasons, !isDigest(plan?.seedCustodyHash), 'seed_custody_hash_invalid');
  addReason(reasons, !isDigest(plan?.blindingPlanHash), 'blinding_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.codeListHash), 'code_list_hash_invalid');
  addReason(reasons, !isDigest(plan?.emergencyUnblindingSopHash), 'emergency_unblinding_sop_hash_invalid');
  addReason(reasons, hlcTuple(plan?.assessedAtHlc) === null, 'assessment_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateAssignment(assignment, input, reasons) {
  const ref = hasText(assignment?.assignmentRef) ? assignment.assignmentRef : 'unknown_assignment';
  addReason(reasons, !hasText(assignment?.assignmentRef), 'assignment_ref_absent');
  addReason(reasons, !isDigest(assignment?.participantCodeHash), `assignment_participant_code_hash_invalid:${ref}`);
  addReason(reasons, assignment?.protocolRef !== input?.randomizationPlan?.protocolRef, `assignment_protocol_mismatch:${ref}`);
  addReason(
    reasons,
    assignment?.protocolVersionRef !== input?.randomizationPlan?.protocolVersionRef,
    `assignment_protocol_version_mismatch:${ref}`,
  );
  addReason(reasons, assignment?.siteRef !== input?.randomizationPlan?.siteRef, `assignment_site_mismatch:${ref}`);
  addReason(reasons, !hasText(assignment?.productLotRef), `assignment_product_lot_absent:${ref}`);
  addReason(reasons, !isDigest(assignment?.assignmentArmHash), `assignment_arm_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(assignment?.randomizationCodeHash), `assignment_randomization_code_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(assignment?.allocationVersionHash), `assignment_allocation_version_hash_invalid:${ref}`);
  addReason(reasons, !hasText(assignment?.assignedByDid), `assignment_actor_absent:${ref}`);
  addReason(reasons, !isDigest(assignment?.assignmentReceiptHash), `assignment_receipt_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(assignment?.assignedAtHlc) === null, `assignment_time_invalid:${ref}`);
  addReason(
    reasons,
    !hlcBeforeOrEqual(assignment?.assignedAtHlc, input?.randomizationPlan?.assessedAtHlc),
    `assignment_after_assessment_or_invalid:${ref}`,
  );
  addReason(
    reasons,
    sortedTextList(assignment?.blindedRoleRefs).length === 0,
    `assignment_blinded_roles_absent:${ref}`,
  );
  addReason(reasons, !hasText(assignment?.unblindedCustodianDid), `assignment_unblinded_custodian_absent:${ref}`);
  addReason(reasons, assignment?.metadataOnly !== true, `assignment_metadata_boundary_invalid:${ref}`);
  addReason(reasons, assignment?.protectedContentExcluded !== true, `assignment_protected_boundary_invalid:${ref}`);
}

function evaluateAssignments(input, reasons) {
  const assignments = Array.isArray(input?.assignments) ? input.assignments : [];
  addReason(reasons, assignments.length === 0, 'assignment_inventory_absent');
  for (const assignment of assignments) {
    evaluateAssignment(assignment, input, reasons);
  }

  const assignmentRefs = sortedTextList(assignments.map((assignment) => assignment?.assignmentRef));
  const participantHashes = sortedTextList(assignments.map((assignment) => assignment?.participantCodeHash));
  const codeHashes = sortedTextList(assignments.map((assignment) => assignment?.randomizationCodeHash));
  addReason(reasons, assignmentRefs.length !== assignments.filter((assignment) => hasText(assignment?.assignmentRef)).length, 'assignment_ref_duplicate');
  addReason(
    reasons,
    participantHashes.length !== assignments.filter((assignment) => hasText(assignment?.participantCodeHash)).length,
    'participant_assignment_duplicate',
  );
  addReason(
    reasons,
    codeHashes.length !== assignments.filter((assignment) => hasText(assignment?.randomizationCodeHash)).length,
    'randomization_code_duplicate',
  );
  return assignments;
}

function assignmentRefs(input) {
  return new Set(sortedTextList((Array.isArray(input?.assignments) ? input.assignments : []).map((assignment) => assignment?.assignmentRef)));
}

function evaluateUnblindingEvent(event, input, allowedAssignmentRefs, reasons) {
  const ref = hasText(event?.eventRef) ? event.eventRef : 'unknown_unblinding_event';
  addReason(reasons, !hasText(event?.eventRef), 'unblinding_event_ref_absent');
  addReason(reasons, !allowedAssignmentRefs.has(event?.assignmentRef), `unblinding_assignment_unknown:${ref}`);
  addReason(reasons, !isDigest(event?.participantCodeHash), `unblinding_participant_code_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(event?.requestedAtHlc) === null, `unblinding_request_time_invalid:${ref}`);
  addReason(reasons, hlcTuple(event?.authorizedAtHlc) === null, `unblinding_authorization_time_invalid:${ref}`);
  addReason(reasons, hlcTuple(event?.reviewedAtHlc) === null, `unblinding_review_time_invalid:${ref}`);
  addReason(reasons, !hlcAfter(event?.authorizedAtHlc, event?.requestedAtHlc), `unblinding_authorization_before_request:${ref}`);
  addReason(reasons, !hlcAfter(event?.reviewedAtHlc, event?.authorizedAtHlc), `unblinding_review_before_authorization:${ref}`);
  addReason(reasons, !hlcBeforeOrEqual(event?.reviewedAtHlc, input?.humanReview?.reviewedAtHlc), `unblinding_review_after_human_review:${ref}`);
  addReason(reasons, event?.authorized !== true, `unblinding_not_authorized:${ref}`);
  addReason(reasons, !hasText(event?.authorizedByDid), `unblinding_authorizer_absent:${ref}`);
  addReason(reasons, !hasText(event?.medicalMonitorDid), `unblinding_medical_monitor_absent:${ref}`);
  addReason(reasons, !isDigest(event?.safetyJustificationHash), `unblinding_safety_justification_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.codeBreakLogHash), `unblinding_code_break_log_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.sponsorNotificationHash), `unblinding_sponsor_notification_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.ethicsNotificationHash), `unblinding_ethics_notification_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.postReviewReceiptHash), `unblinding_post_review_receipt_hash_invalid:${ref}`);
  addReason(reasons, event?.metadataOnly !== true, `unblinding_metadata_boundary_invalid:${ref}`);
  addReason(reasons, event?.protectedContentExcluded !== true, `unblinding_protected_boundary_invalid:${ref}`);
}

function evaluateUnblindingEvents(input, reasons) {
  const events = Array.isArray(input?.emergencyUnblindingEvents) ? input.emergencyUnblindingEvents : [];
  const allowedAssignmentRefs = assignmentRefs(input);
  for (const event of events) {
    evaluateUnblindingEvent(event, input, allowedAssignmentRefs, reasons);
  }
  return events;
}

function evaluateBlindingControls(input, reasons) {
  const controls = input?.blindingControls;
  addReason(reasons, controls?.allocationConcealmentMaintained !== true, 'allocation_concealment_not_maintained');
  addReason(reasons, controls?.unblindedRolesSeparated !== true, 'unblinded_roles_not_separated');
  addReason(reasons, controls?.participantIdentifiersSuppressed !== true, 'participant_identifier_suppression_absent');
  addReason(reasons, !Number.isSafeInteger(controls?.openCodeBreakCount) || controls.openCodeBreakCount < 0, 'open_code_break_count_invalid');
  addReason(reasons, Number.isSafeInteger(controls?.openCodeBreakCount) && controls.openCodeBreakCount > 0, 'open_code_breaks_present');
  addReason(reasons, !isDigest(controls?.codeListAccessPolicyHash), 'code_list_access_policy_hash_invalid');
  addReason(reasons, !isDigest(controls?.randomizationSystemValidationHash), 'randomization_system_validation_hash_invalid');
  addReason(reasons, !isDigest(controls?.blindingAccessReviewHash), 'blinding_access_review_hash_invalid');
  addReason(reasons, !hasText(controls?.productAccountabilityRef), 'product_accountability_ref_absent');
  addReason(reasons, !isDigest(controls?.productAccountabilityHash), 'product_accountability_hash_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_boundary_invalid');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_boundary_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !hasText(review?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, !hasText(review?.unblindedCustodianDid), 'unblinded_custodian_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, review?.decision !== 'randomization_blinding_ready', 'randomization_blinding_not_ready');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'evidence_bundle_hash_invalid');
  addReason(reasons, review?.decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, review?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, review?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, review?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, review?.decisionForum?.openChallenge === true, 'decision_forum_challenge_open');
  addReason(reasons, !hasText(review?.decisionForum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(review?.decisionForum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function reasonPrefixBlocked(reasons, prefixes) {
  return reasons.some((reason) => prefixes.some((prefix) => reason.startsWith(prefix)));
}

function buildRandomizationBlinding(input, coveredDomains, assignments, events, reasons) {
  const material = {
    schema: `${RANDOMIZATION_BLINDING_SCHEMA}.material.v1`,
    tenantId: input?.tenantId ?? '',
    planRef: input?.randomizationPlan?.planRef ?? '',
    protocolRef: input?.randomizationPlan?.protocolRef ?? '',
    protocolVersionRef: input?.randomizationPlan?.protocolVersionRef ?? '',
    siteRef: input?.randomizationPlan?.siteRef ?? '',
    sponsorRef: input?.randomizationPlan?.sponsorRef ?? '',
    assignmentRefs: sortedTextList(assignments.map((assignment) => assignment?.assignmentRef)),
    participantCodeHashes: sortedTextList(assignments.map((assignment) => assignment?.participantCodeHash)),
    randomizationCodeHashes: sortedTextList(assignments.map((assignment) => assignment?.randomizationCodeHash)),
    unblindingEventRefs: sortedTextList(events.map((event) => event?.eventRef)),
    coveredDomains,
    requiredDomains: REQUIRED_RANDOMIZATION_DOMAINS,
    openCodeBreakCount: Number.isSafeInteger(input?.blindingControls?.openCodeBreakCount)
      ? input.blindingControls.openCodeBreakCount
      : 0,
    productAccountabilityRef: input?.blindingControls?.productAccountabilityRef ?? '',
    humanReviewerDid: input?.humanReview?.reviewerDid ?? '',
    decisionForumId: input?.humanReview?.decisionForum?.decisionId ?? '',
    reasons,
  };
  const randomizationBlindingHash = sha256Hex(material);
  const blocked = reasons.length > 0;
  return {
    schema: RANDOMIZATION_BLINDING_SCHEMA,
    randomizationBlindingId: `cmrb_${randomizationBlindingHash.slice(0, 32)}`,
    randomizationBlindingHash,
    tenantId: material.tenantId,
    planRef: material.planRef,
    protocolRef: material.protocolRef,
    protocolVersionRef: material.protocolVersionRef,
    siteRef: material.siteRef,
    readinessStatus: blocked ? 'blocked' : 'ready',
    assignmentStatus: reasonPrefixBlocked(reasons, ['assignment_', 'participant_assignment_', 'randomization_code_']) ? 'blocked' : 'ready',
    blindingStatus: reasonPrefixBlocked(reasons, ['allocation_', 'unblinded_', 'participant_identifier_', 'open_code_', 'controls_', 'code_list_'])
      ? 'blocked'
      : 'ready',
    unblindingStatus: reasonPrefixBlocked(reasons, ['unblinding_']) ? 'blocked' : 'controlled',
    assignmentCount: assignments.length,
    emergencyUnblindingEventCount: events.length,
    openCodeBreakCount: material.openCodeBreakCount,
    requiredDomains: REQUIRED_RANDOMIZATION_DOMAINS,
    coveredDomains,
    participantCodeHashes: material.participantCodeHashes,
    randomizationCodeHashes: material.randomizationCodeHashes,
    productAccountabilityRef: material.productAccountabilityRef,
    aiFinalAuthority: input?.humanReview?.aiFinalAuthority === true,
    exochainProductionClaim: false,
    containsProtectedContent: false,
    trustState: 'inactive',
  };
}

function buildReceipt(input, randomizationBlindingHash) {
  return createEvidenceReceipt({
    tenantId: input?.tenantId,
    actorDid: input?.actor?.did,
    artifactType: 'randomization_blinding_management',
    artifactVersion: input?.randomizationPlan?.protocolVersionRef,
    artifactHash: randomizationBlindingHash,
    classification: 'randomization_blinding_management_metadata_only',
    sensitivityTags: ['clinical_trial_product_metadata', 'randomization_blinding', 'metadata_only'],
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.humanReview?.reviewedAtHlc,
    sourceSystem: 'cybermedica.randomization_blinding_management',
  });
}

export function evaluateRandomizationBlindingManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const { coveredDomains } = evaluateRequiredDomains(input, reasons);
  evaluateRandomizationPlan(input, reasons);
  const assignments = evaluateAssignments(input, reasons);
  const events = evaluateUnblindingEvents(input, reasons);
  evaluateBlindingControls(input, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  const randomizationBlinding = buildRandomizationBlinding(input, coveredDomains, assignments, events, uniqueReasons);
  const denied = uniqueReasons.length > 0;

  return {
    schema: 'cybermedica.randomization_blinding_management_decision.v1',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reasons: uniqueReasons,
    denialReasons: uniqueReasons,
    randomizationBlinding,
    receipt: denied ? null : buildReceipt(input, randomizationBlinding.randomizationBlindingHash),
  };
}
