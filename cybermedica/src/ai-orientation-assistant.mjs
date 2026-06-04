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
const ORIENTATION_SCHEMA = 'cybermedica.ai_orientation_assistant.v1';
const REQUIRED_PERMISSION = 'ai_orientation_review';
const REQUIRED_GUIDANCE_LABEL = 'guidance_not_policy_authority';

const REQUIRED_CONTEXT_FIELDS = Object.freeze([
  'active_object',
  'available_manuals',
  'tenant_context',
  'user_role',
  'workflow_state',
]);

const REQUIRED_CITATION_FAMILIES = Object.freeze([
  'control',
  'manual_section',
  'procedure',
]);

const REQUIRED_SIGNAL_FAMILIES = Object.freeze([
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_orientation_assistant_gap',
  'orientation_assistant_ready_inactive_trust',
]);

const RAW_ORIENTATION_FIELDS = new Set([
  'answer',
  'answerbody',
  'answercontent',
  'answertext',
  'assistantanswer',
  'assistantbody',
  'assistantoutput',
  'body',
  'content',
  'freetext',
  'freetextnote',
  'guidancebody',
  'guidancecontent',
  'guidancetext',
  'helpbody',
  'helpcontent',
  'manualbody',
  'manualcontent',
  'manualtext',
  'notes',
  'orientationcopy',
  'questionbody',
  'questioncontent',
  'questiontext',
  'rawanswer',
  'rawassistantcontent',
  'rawcontent',
  'rawguidance',
  'rawhelpcontent',
  'rawinquirycontent',
  'rawmanualcontent',
  'rawprompt',
  'rawquestion',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
]);

const SECRET_ORIENTATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawOrientationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawOrientationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ORIENTATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw AI orientation assistant field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ORIENTATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`AI orientation assistant secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawOrientationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawOrientationContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_orientation_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'orientation_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredContextFields = sortedTextList(policy?.requiredContextFields);
  const requiredCitationFamilies = sortedTextList(policy?.requiredCitationFamilies);
  const requiredConfusionSignalFamilies = sortedTextList(policy?.requiredConfusionSignalFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'orientation_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'orientation_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'orientation_policy_not_active');
  addReason(reasons, policy?.guidanceLabel !== REQUIRED_GUIDANCE_LABEL, 'orientation_policy_guidance_label_invalid');
  addReason(reasons, policy?.cqiReportingRequired !== true, 'orientation_policy_cqi_reporting_absent');
  addReason(
    reasons,
    policy?.unresolvedQuestionHumanRouteRequired !== true,
    'orientation_policy_unresolved_question_route_absent',
  );
  addReason(reasons, policy?.advisoryOnly !== true, 'orientation_policy_not_advisory');
  addReason(reasons, policy?.allowAiFinalAuthority === true, 'orientation_policy_allows_ai_final_authority');
  addReason(reasons, policy?.metadataOnly !== true, 'orientation_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'orientation_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'orientation_policy_time_invalid');
  evaluateRequiredSet(
    requiredContextFields,
    REQUIRED_CONTEXT_FIELDS,
    'policy_context_field_missing',
    'policy_context_field_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredCitationFamilies,
    REQUIRED_CITATION_FAMILIES,
    'policy_citation_family_missing',
    'policy_citation_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredConfusionSignalFamilies,
    REQUIRED_SIGNAL_FAMILIES,
    'policy_confusion_signal_missing',
    'policy_confusion_signal_unsupported',
    reasons,
  );

  return {
    requiredCitationFamilies,
    requiredConfusionSignalFamilies,
    requiredContextFields,
  };
}

function evaluateRequestContext(context, policy, reasons) {
  const availableManualRefs = sortedTextList(context?.availableManualRefs);
  addReason(reasons, !hasText(context?.requestRef), 'request_context_ref_absent');
  addReason(reasons, !hasText(context?.userRoleRef), 'request_context_user_role_absent');
  addReason(reasons, !hasText(context?.tenantContextRef), 'request_context_tenant_context_absent');
  addReason(reasons, !hasText(context?.activeObjectType), 'request_context_active_object_type_absent');
  addReason(reasons, !hasText(context?.activeObjectRef), 'request_context_active_object_absent');
  addReason(reasons, !hasText(context?.workflowRef), 'request_context_workflow_ref_absent');
  addReason(reasons, !hasText(context?.workflowStateRef), 'request_context_workflow_state_absent');
  addReason(reasons, availableManualRefs.length === 0, 'request_context_available_manuals_absent');
  addReason(reasons, !isDigest(context?.manualIndexHash), 'request_context_manual_index_hash_invalid');
  addReason(reasons, !isDigest(context?.contextualDrawerReceiptHash), 'request_context_drawer_receipt_hash_invalid');
  addReason(reasons, context?.metadataOnly !== true, 'request_context_metadata_boundary_invalid');
  addReason(reasons, context?.protectedContentExcluded !== true, 'request_context_protected_boundary_invalid');
  addReason(reasons, hlcTuple(context?.requestedAtHlc) === null, 'request_context_time_invalid');
  addReason(reasons, !hlcAfter(context?.requestedAtHlc, policy?.evaluatedAtHlc), 'request_context_before_policy');

  const contextCoverage = [];
  if (hasText(context?.activeObjectType) && hasText(context?.activeObjectRef)) {
    contextCoverage.push('active_object');
  }
  if (availableManualRefs.length > 0) {
    contextCoverage.push('available_manuals');
  }
  if (hasText(context?.tenantContextRef)) {
    contextCoverage.push('tenant_context');
  }
  if (hasText(context?.userRoleRef)) {
    contextCoverage.push('user_role');
  }
  if (hasText(context?.workflowRef) && hasText(context?.workflowStateRef)) {
    contextCoverage.push('workflow_state');
  }
  evaluateRequiredSet(
    uniqueSorted(contextCoverage),
    REQUIRED_CONTEXT_FIELDS,
    'request_context_field_missing',
    'request_context_field_unsupported',
    reasons,
  );

  return uniqueSorted(contextCoverage);
}

function evaluateGuidanceAnswer(answer, policy, context, reasons) {
  addReason(reasons, !hasText(answer?.answerRef), 'guidance_answer_ref_absent');
  addReason(reasons, !isDigest(answer?.guidanceHash), 'guidance_hash_invalid');
  addReason(reasons, answer?.guidanceLabel !== policy?.guidanceLabel, 'guidance_label_invalid');
  addReason(reasons, !isBasisPoints(answer?.confidenceBasisPoints), 'guidance_confidence_invalid');
  addReason(reasons, typeof answer?.unresolvedQuestion !== 'boolean', 'guidance_unresolved_question_flag_invalid');
  addReason(
    reasons,
    answer?.unresolvedQuestion === true && !hasText(answer?.humanEscalationRoleRef),
    'guidance_unresolved_question_route_absent',
  );
  addReason(reasons, answer?.advisoryOnly !== true, 'guidance_not_advisory');
  addReason(reasons, answer?.finalAuthority === true, 'guidance_final_authority_forbidden');
  addReason(reasons, answer?.citesLinkedSources !== true, 'guidance_linked_source_citation_missing');
  addReason(reasons, answer?.metadataOnly !== true, 'guidance_metadata_boundary_invalid');
  addReason(reasons, answer?.protectedContentExcluded !== true, 'guidance_protected_boundary_invalid');
  addReason(reasons, hlcTuple(answer?.generatedAtHlc) === null, 'guidance_generated_time_invalid');
  addReason(reasons, !hlcAfter(answer?.generatedAtHlc, context?.requestedAtHlc), 'guidance_generated_before_request');
}

function citationLabel(citation, index) {
  return hasText(citation?.citationRef) ? citation.citationRef : `citation_${index}`;
}

function evaluateCitations(citations, reasons) {
  const rows = Array.isArray(citations) ? [...citations] : [];
  addReason(reasons, rows.length === 0, 'citations_absent');
  const seenRefs = new Set();
  const families = uniqueSorted(rows.map((row) => row?.family));
  evaluateRequiredSet(
    families,
    REQUIRED_CITATION_FAMILIES,
    'citation_family_missing',
    'citation_family_unsupported',
    reasons,
  );

  for (const [index, citation] of rows.entries()) {
    const label = citationLabel(citation, index);
    addReason(reasons, !hasText(citation?.citationRef), `citation_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(citation?.citationRef), `citation_ref_duplicate:${label}`);
    if (hasText(citation?.citationRef)) {
      seenRefs.add(citation.citationRef);
    }
    addReason(reasons, !REQUIRED_CITATION_FAMILIES.includes(citation?.family), `citation_family_invalid:${label}`);
    addReason(reasons, !hasText(citation?.targetRef), `citation_target_ref_absent:${label}`);
    addReason(reasons, !isDigest(citation?.targetHash), `citation_target_hash_invalid:${label}`);
    addReason(reasons, !hasText(citation?.manualSectionRef), `citation_manual_section_ref_absent:${label}`);
    addReason(reasons, !hasText(citation?.relationToActiveObject), `citation_relation_absent:${label}`);
    addReason(reasons, !isPositiveSafeInteger(citation?.displayOrder), `citation_display_order_invalid:${label}`);
    addReason(reasons, citation?.metadataOnly !== true, `citation_metadata_boundary_invalid:${label}`);
    addReason(reasons, citation?.protectedContentExcluded !== true, `citation_protected_boundary_invalid:${label}`);
  }

  return families;
}

function evaluateConfusionReporter(reporter, guidanceAnswer, reasons) {
  const requiredSignalFamilies = sortedTextList(reporter?.requiredSignalFamilies);
  addReason(reasons, !hasText(reporter?.reporterRef), 'confusion_reporter_ref_absent');
  addReason(reasons, reporter?.enabled !== true, 'confusion_reporter_disabled');
  addReason(reasons, reporter?.capturesRoleContext !== true, 'confusion_reporter_role_context_missing');
  addReason(reasons, reporter?.capturesTenantContext !== true, 'confusion_reporter_tenant_context_missing');
  addReason(reasons, reporter?.capturesActiveObjectContext !== true, 'confusion_reporter_active_object_context_missing');
  addReason(reasons, reporter?.capturesWorkflowState !== true, 'confusion_reporter_workflow_state_missing');
  addReason(
    reasons,
    reporter?.capturesManualSectionContext !== true,
    'confusion_reporter_manual_section_context_missing',
  );
  addReason(
    reasons,
    reporter?.capturesSuggestedImprovementCategory !== true,
    'confusion_reporter_improvement_category_missing',
  );
  addReason(reasons, !hasText(reporter?.cqiRouteRef), 'confusion_reporter_cqi_route_absent');
  addReason(reasons, !isDigest(reporter?.inquiryCqiPolicyHash), 'confusion_reporter_policy_hash_invalid');
  addReason(reasons, reporter?.noRawInquiryContent !== true, 'confusion_reporter_raw_inquiry_boundary_absent');
  addReason(reasons, reporter?.metadataOnly !== true, 'confusion_reporter_metadata_boundary_invalid');
  addReason(reasons, reporter?.protectedContentExcluded !== true, 'confusion_reporter_protected_boundary_invalid');
  addReason(reasons, hlcTuple(reporter?.reviewedAtHlc) === null, 'confusion_reporter_review_time_invalid');
  addReason(
    reasons,
    !hlcAfter(reporter?.reviewedAtHlc, guidanceAnswer?.generatedAtHlc),
    'confusion_reporter_review_before_guidance',
  );
  evaluateRequiredSet(
    requiredSignalFamilies,
    REQUIRED_SIGNAL_FAMILIES,
    'confusion_reporter_signal_missing',
    'confusion_reporter_signal_unsupported',
    reasons,
  );

  return requiredSignalFamilies;
}

function evaluateHumanReview(humanReview, reporter, reasons) {
  const reviewerRoleRefs = sortedTextList(humanReview?.reviewerRoleRefs);
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, reviewerRoleRefs.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(humanReview?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, humanReview?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, humanReview?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(
    reasons,
    humanReview?.noProductionTrustClaim !== true,
    'human_review_production_trust_claim_forbidden',
  );
  addReason(reasons, humanReview?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(humanReview?.reviewedAtHlc, reporter?.reviewedAtHlc), 'human_review_before_reporter');
}

function createRecordDigest(input, contextCoverage, citationFamilies, confusionSignalFamilies) {
  return sha256Hex({
    activeObjectRef: input?.requestContext?.activeObjectRef ?? null,
    answerRef: input?.guidanceAnswer?.answerRef ?? null,
    citationFamilies,
    citationRefs: uniqueSorted((Array.isArray(input?.citations) ? input.citations : []).map((row) => row?.citationRef)),
    confusionSignalFamilies,
    contextCoverage,
    guidanceHash: input?.guidanceAnswer?.guidanceHash ?? null,
    guidanceLabel: input?.guidanceAnswer?.guidanceLabel ?? null,
    manualIndexHash: input?.requestContext?.manualIndexHash ?? null,
    policyHash: input?.orientationPolicy?.policyHash ?? null,
    requestRef: input?.requestContext?.requestRef ?? null,
    workflowStateRef: input?.requestContext?.workflowStateRef ?? null,
  });
}

function createOrientationRecord(input, contextCoverage, citationFamilies, confusionSignalFamilies) {
  const recordHash = createRecordDigest(input, contextCoverage, citationFamilies, confusionSignalFamilies);
  return {
    schema: ORIENTATION_SCHEMA,
    recordHash,
    requestRef: input.requestContext.requestRef,
    answerRef: input.guidanceAnswer.answerRef,
    activeObjectRef: input.requestContext.activeObjectRef,
    workflowStateRef: input.requestContext.workflowStateRef,
    guidanceLabel: input.guidanceAnswer.guidanceLabel,
    guidanceHash: input.guidanceAnswer.guidanceHash,
    contextCoverage,
    citationFamilies,
    confusionSignalFamilies,
    cqiReporterReady: true,
    unresolvedQuestionRoutedToHuman:
      input.guidanceAnswer.unresolvedQuestion === true && hasText(input.guidanceAnswer.humanEscalationRoleRef),
    advisoryOnly: input.guidanceAnswer.advisoryOnly === true,
    aiFinalAuthority: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    reviewerDid: input.humanReview.reviewerDid,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md:DOC-005',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md:DOC-006',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function createReceipt(input, orientationRecord) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: orientationRecord.recordHash,
    artifactType: 'ai_orientation_assistant',
    artifactVersion: input.guidanceAnswer.answerRef,
    classification: 'metadata_only_orientation_guidance',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['orientation_guidance_metadata', 'manual_citation_metadata', 'no_raw_content'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateAiOrientationAssistant(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.orientationPolicy, reasons);
  const contextCoverage = evaluateRequestContext(input?.requestContext, input?.orientationPolicy, reasons);
  evaluateGuidanceAnswer(input?.guidanceAnswer, input?.orientationPolicy, input?.requestContext, reasons);
  const citationFamilies = evaluateCitations(input?.citations, reasons);
  const confusionSignalFamilies = evaluateConfusionReporter(input?.confusionReporter, input?.guidanceAnswer, reasons);
  evaluateHumanReview(input?.humanReview, input?.confusionReporter, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  if (finalReasons.length > 0) {
    return {
      schema: ORIENTATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      orientationRecord: null,
      receipt: null,
    };
  }

  const orientationRecord = createOrientationRecord(input, contextCoverage, citationFamilies, confusionSignalFamilies);
  return {
    schema: ORIENTATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    orientationRecord,
    receipt: createReceipt(input, orientationRecord),
  };
}
