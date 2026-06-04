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
const REQUIRED_PERMISSION = 'contest_ai_recommendation';
const CONTESTATION_SCHEMA = 'cybermedica.ai_recommendation_contestation.v1';
const DECISION_SCHEMA = 'cybermedica.ai_recommendation_contestation_decision.v1';

const SOURCE_WORKFLOWS = new Set([
  'ai-control-review',
  'ai-gap-recommendation-queue',
  'ai-quality-review-workbench',
  'assistant-explainability',
  'documentation-publication',
  'governed-reporting',
  'protocol-feasibility',
  'site-self-assessments',
]);

const ALLOWED_REASON_CODES = Object.freeze([
  'conflict_or_recusal_gap',
  'data_integrity_concern',
  'evidence_gap',
  'participant_safety_concern',
  'privacy_boundary_concern',
]);

const REQUIRED_CONTESTATION_FAMILIES = Object.freeze([
  'advisory_label',
  'evidence_basis',
  'human_reviewer',
  'limitation_record',
  'reason_code',
  'standing_policy',
  'timely_filing',
]);

export const REQUIRED_AI_RECOMMENDATION_CONTESTATION_FAMILIES = Object.freeze([
  ...REQUIRED_CONTESTATION_FAMILIES,
]);

const ALLOWED_FILER_ROLES = new Set([
  'clinical_research_coordinator',
  'decision_forum_member',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_monitor',
]);

const REQUESTED_OUTCOMES = new Set([
  'clarification',
  'decision_forum_review',
  'human_override_review',
  'withdraw_recommendation',
]);

const REVIEW_DECISIONS = new Set([
  'accepted_for_review',
  'rejected_no_standing',
  'resolved_human_override',
  'routed_to_decision_forum',
]);

const DECISION_FORUM_STATES = new Set(['accepted_for_review', 'routed']);
const HUMAN_DISPOSITIONS = new Set([
  'human_governance_review_pending',
  'human_override_recorded',
  'recommendation_withdrawal_required',
]);

const RAW_RECOMMENDATION_FIELDS = new Set([
  'hiddenconclusion',
  'modeloutputbody',
  'promptbody',
  'rawairecommendation',
  'rawconclusion',
  'rawmodeloutput',
  'rawprompt',
  'rawrecommendation',
  'rawrecommendationbody',
  'rawreview',
  'recommendationbody',
  'sourcedocumentbody',
  'verbatimrecommendation',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoRawRecommendationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRecommendationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RECOMMENDATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw AI recommendation content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`AI recommendation contestation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRecommendationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRecommendationContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'ai_contestation_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRecommendation(recommendation, reasons) {
  addReason(reasons, recommendation === null || recommendation === undefined, 'recommendation_absent');
  addReason(reasons, !hasText(recommendation?.recommendationRef), 'recommendation_ref_absent');
  addReason(reasons, !SOURCE_WORKFLOWS.has(recommendation?.sourceWorkflowRef), 'recommendation_source_workflow_unsupported');
  addReason(reasons, !isDigest(recommendation?.sourceWorkflowReceiptHash), 'source_workflow_receipt_hash_invalid');
  addReason(reasons, !isDigest(recommendation?.recommendationHash), 'recommendation_hash_invalid');
  addReason(reasons, !hasText(recommendation?.modelRef), 'model_ref_absent');
  addReason(reasons, !isDigest(recommendation?.modelVersionHash), 'model_version_hash_invalid');
  addReason(reasons, !isDigest(recommendation?.evidenceBundleHash), 'evidence_bundle_hash_invalid');
  addReason(reasons, !isDigest(recommendation?.reasoningSummaryHash), 'reasoning_summary_hash_invalid');
  for (const hash of sortedTextList(recommendation?.limitationHashes)) {
    addReason(reasons, !isDigest(hash), 'limitation_hash_invalid');
  }
  addReason(reasons, !isBasisPoints(recommendation?.confidenceBasisPoints), 'confidence_basis_points_invalid');
  addReason(reasons, recommendation?.advisoryOnly !== true, 'recommendation_must_be_advisory');
  addReason(reasons, recommendation?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, recommendation?.humanDispositionRequired !== true, 'human_disposition_required_absent');
  addReason(reasons, recommendation?.contestable !== true, 'recommendation_contestability_absent');
  addReason(reasons, hlcTuple(recommendation?.generatedAtHlc) === null, 'recommendation_time_invalid');
  addReason(reasons, recommendation?.metadataOnly !== true, 'recommendation_metadata_boundary_invalid');
  addReason(reasons, recommendation?.protectedContentExcluded !== true, 'recommendation_protected_boundary_invalid');
  addReason(reasons, recommendation?.productionTrustClaim === true, 'recommendation_production_trust_claim_forbidden');
}

function evaluateStandingPolicy(policy, reasons) {
  const allowedFilerRoles = sortedTextList(policy?.allowedFilerRoles);
  const allowedReasonCodes = sortedTextList(policy?.allowedReasonCodes);
  const families = sortedTextList(policy?.requiredContestabilityFamilies);

  addReason(reasons, policy === null || policy === undefined, 'standing_policy_absent');
  addReason(reasons, !hasText(policy?.policyRef), 'standing_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'standing_policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'standing_policy_not_active');
  addReason(reasons, allowedFilerRoles.length === 0, 'allowed_filer_roles_absent');
  addReason(reasons, allowedReasonCodes.length === 0, 'allowed_reason_codes_absent');
  evaluateRequiredSet(families, REQUIRED_CONTESTATION_FAMILIES, 'contestability_family_missing', 'contestability_family_unsupported', reasons);
  for (const role of allowedFilerRoles) {
    addReason(reasons, !ALLOWED_FILER_ROLES.has(role), `allowed_filer_role_unsupported:${role}`);
  }
  for (const reason of allowedReasonCodes) {
    addReason(reasons, !ALLOWED_REASON_CODES.includes(reason), `allowed_reason_code_unsupported:${reason}`);
  }
  addReason(reasons, hlcTuple(policy?.challengeWindowClosesAtHlc) === null, 'challenge_window_close_time_invalid');
  addReason(reasons, policy?.independentReviewRequired !== true, 'independent_review_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'standing_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'standing_policy_protected_boundary_invalid');

  return { allowedFilerRoles, allowedReasonCodes, families };
}

function evaluateContestation(contestation, recommendation, policy, policySummary, reasons) {
  addReason(reasons, contestation === null || contestation === undefined, 'contestation_absent');
  addReason(reasons, !hasText(contestation?.contestRef), 'contest_ref_absent');
  addReason(reasons, !hasText(contestation?.filerDid), 'filer_did_absent');
  addReason(reasons, !hasText(contestation?.filerRoleRef), 'filer_role_absent');
  addReason(
    reasons,
    hasText(contestation?.filerRoleRef) && !policySummary.allowedFilerRoles.includes(contestation.filerRoleRef),
    'filer_role_not_allowed',
  );
  addReason(reasons, !ALLOWED_REASON_CODES.includes(contestation?.reasonCode), 'contest_reason_unsupported');
  addReason(
    reasons,
    hasText(contestation?.reasonCode) && !policySummary.allowedReasonCodes.includes(contestation.reasonCode),
    'contest_reason_not_allowed',
  );
  addReason(reasons, !isDigest(contestation?.reasonHash), 'contest_reason_hash_invalid');
  addReason(reasons, !REQUESTED_OUTCOMES.has(contestation?.requestedOutcome), 'requested_outcome_unsupported');
  addReason(reasons, typeof contestation?.materialImpact !== 'boolean', 'material_impact_flag_invalid');
  addReason(reasons, typeof contestation?.affectsParticipantSafety !== 'boolean', 'participant_safety_impact_flag_invalid');
  addReason(reasons, typeof contestation?.affectsDataIntegrity !== 'boolean', 'data_integrity_impact_flag_invalid');
  addReason(reasons, typeof contestation?.affectsPrivacy !== 'boolean', 'privacy_impact_flag_invalid');
  addReason(reasons, hlcTuple(contestation?.filedAtHlc) === null, 'contest_filed_time_invalid');
  addReason(
    reasons,
    hlcTuple(contestation?.filedAtHlc) !== null &&
      hlcTuple(recommendation?.generatedAtHlc) !== null &&
      !hlcAfter(contestation.filedAtHlc, recommendation.generatedAtHlc),
    'contest_filed_before_recommendation',
  );
  addReason(
    reasons,
    hlcTuple(contestation?.filedAtHlc) !== null &&
      hlcTuple(policy?.challengeWindowClosesAtHlc) !== null &&
      !hlcBeforeOrEqual(contestation.filedAtHlc, policy.challengeWindowClosesAtHlc),
    'contest_filed_after_challenge_window',
  );
  addReason(reasons, contestation?.metadataOnly !== true, 'contestation_metadata_boundary_invalid');
  addReason(reasons, contestation?.protectedContentExcluded !== true, 'contestation_protected_boundary_invalid');
}

function evaluateIndependentReview(review, contestation, reasons) {
  addReason(reasons, review === null || review === undefined, 'independent_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'independent_reviewer_absent');
  addReason(reasons, !hasText(review?.reviewerRoleRef), 'independent_reviewer_role_absent');
  addReason(reasons, review?.independentFromAiOwner !== true, 'independent_review_conflict');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'independent_review_evidence_hash_invalid');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'independent_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionRationaleHash), 'independent_review_rationale_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'independent_review_time_invalid');
  addReason(
    reasons,
    hlcTuple(review?.reviewedAtHlc) !== null &&
      hlcTuple(contestation?.filedAtHlc) !== null &&
      !hlcAfter(review.reviewedAtHlc, contestation.filedAtHlc),
    'independent_review_before_contestation',
  );
  addReason(reasons, review?.metadataOnly !== true, 'independent_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'independent_review_protected_boundary_invalid');
}

function contestationIsMaterial(contestation) {
  return (
    contestation?.materialImpact === true ||
    contestation?.affectsParticipantSafety === true ||
    contestation?.affectsDataIntegrity === true ||
    contestation?.affectsPrivacy === true
  );
}

function evaluateDecisionForum(forum, policy, material, reasons) {
  if (!material) {
    return;
  }

  addReason(reasons, policy?.decisionForumRequiredForMaterial !== true, 'material_contestation_decision_forum_policy_absent');
  addReason(reasons, forum === null || forum === undefined, 'material_contestation_decision_forum_absent');
  addReason(reasons, !hasText(forum?.matterRef), 'material_contestation_decision_forum_matter_absent');
  addReason(reasons, !isDigest(forum?.routingReceiptHash), 'material_contestation_decision_forum_receipt_hash_invalid');
  addReason(reasons, !DECISION_FORUM_STATES.has(forum?.state), 'material_contestation_decision_forum_state_invalid');
  addReason(reasons, forum?.humanGate?.verified !== true, 'material_contestation_human_gate_unverified');
  addReason(reasons, forum?.openChallenge === true, 'material_contestation_open_challenge');
  addReason(reasons, forum?.metadataOnly !== true, 'decision_forum_metadata_boundary_invalid');
  addReason(reasons, forum?.protectedContentExcluded !== true, 'decision_forum_protected_boundary_invalid');
}

function evaluateHumanDisposition(disposition, review, reasons) {
  addReason(reasons, disposition === null || disposition === undefined, 'human_disposition_absent');
  addReason(reasons, disposition?.finalAuthority !== 'human', 'human_disposition_ai_final_authority_forbidden');
  addReason(reasons, disposition?.aiFinalAuthorityRejected !== true, 'human_disposition_ai_rejection_absent');
  addReason(reasons, !HUMAN_DISPOSITIONS.has(disposition?.disposition), 'human_disposition_invalid');
  addReason(reasons, !isDigest(disposition?.dispositionHash), 'human_disposition_hash_invalid');
  addReason(reasons, hlcTuple(disposition?.recordedAtHlc) === null, 'human_disposition_time_invalid');
  addReason(
    reasons,
    hlcTuple(disposition?.recordedAtHlc) !== null &&
      hlcTuple(review?.reviewedAtHlc) !== null &&
      !hlcAfter(disposition.recordedAtHlc, review.reviewedAtHlc),
    'human_disposition_before_independent_review',
  );
  addReason(reasons, disposition?.metadataOnly !== true, 'human_disposition_metadata_boundary_invalid');
  addReason(reasons, disposition?.protectedContentExcluded !== true, 'human_disposition_protected_boundary_invalid');
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function recordStatus(review, material) {
  if (material && review?.decision === 'routed_to_decision_forum') {
    return 'routed_to_decision_forum';
  }
  if (review?.decision === 'resolved_human_override') {
    return 'resolved_human_override';
  }
  if (review?.decision === 'rejected_no_standing') {
    return 'rejected_no_standing';
  }
  return 'accepted_for_independent_review';
}

function buildRecord(input, policySummary, material) {
  const status = recordStatus(input.independentReview, material);
  const recordCore = {
    allowedReasonCodes: policySummary.allowedReasonCodes,
    contestRef: input.contestation.contestRef,
    contestabilityFamilies: REQUIRED_CONTESTATION_FAMILIES,
    filedAtHlc: input.contestation.filedAtHlc,
    filerDid: input.contestation.filerDid,
    filerRoleRef: input.contestation.filerRoleRef,
    humanDispositionHash: input.humanDisposition.dispositionHash,
    independentReviewDecision: input.independentReview.decision,
    materialImpact: material,
    recommendationHash: input.recommendation.recommendationHash,
    recommendationRef: input.recommendation.recommendationRef,
    reasonCode: input.contestation.reasonCode,
    reasonHash: input.contestation.reasonHash,
    schema: CONTESTATION_SCHEMA,
    sourceWorkflowReceiptHash: input.recommendation.sourceWorkflowReceiptHash,
    sourceWorkflowRef: input.recommendation.sourceWorkflowRef,
    standingPolicyHash: input.standingPolicy.policyHash,
    status,
    tenantId: input.tenantId,
  };
  const recordHash = sha256Hex(recordCore);

  return {
    ...recordCore,
    recordHash,
    aiFinalAuthorityRejected: input.humanDisposition.aiFinalAuthorityRejected === true,
    decisionForumMatterRef: material ? input.decisionForum?.matterRef ?? null : null,
    exochainProductionClaim: false,
    metadataOnly: true,
    requestedOutcome: input.contestation.requestedOutcome,
    trustState: 'inactive',
  };
}

function buildReceipt(input, record) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: record.recordHash,
    artifactType: 'ai_recommendation_contestation',
    artifactVersion: `${input.recommendation.recommendationRef}@${input.contestation.contestRef}`,
    classification: 'metadata_only_ai_recommendation_contestation',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.contestation.filedAtHlc,
    sensitivityTags: ['ai_recommendation', 'contestable', 'human_governance', 'metadata_only'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateAiRecommendationContestation(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateRecommendation(input?.recommendation, reasons);
  const policySummary = evaluateStandingPolicy(input?.standingPolicy, reasons);
  evaluateContestation(input?.contestation, input?.recommendation, input?.standingPolicy, policySummary, reasons);
  evaluateIndependentReview(input?.independentReview, input?.contestation, reasons);
  const material = contestationIsMaterial(input?.contestation);
  evaluateDecisionForum(input?.decisionForum, input?.standingPolicy, material, reasons);
  evaluateHumanDisposition(input?.humanDisposition, input?.independentReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: denialReasons,
      contestationRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const contestationRecord = buildRecord(input, policySummary, material);
  const receipt = buildReceipt(input, contestationRecord);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    contestationRecord,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
