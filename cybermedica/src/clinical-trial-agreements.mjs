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

const REQUIRED_REVIEW_DIMENSIONS = Object.freeze([
  'duties',
  'functions',
  'financial_requirements',
  'qa_qc_requirements',
  'reporting_procedures',
  'termination_suspension_requirements',
  'document_retention',
  'data_access',
  'monitoring',
  'inspection',
  'audit_rights',
]);
const REQUIRED_DIMENSION_SET = new Set(REQUIRED_REVIEW_DIMENSIONS);
const REVIEW_STATUSES = new Set(['accepted', 'accepted_with_conditions']);
const ISSUE_SEVERITIES = Object.freeze(['critical', 'major', 'minor']);
const ISSUE_SEVERITY_SET = new Set(ISSUE_SEVERITIES);
const ISSUE_RESOLVED_STATUSES = new Set(['accepted', 'closed', 'mitigated', 'resolved']);
const EXECUTED_STATES = new Set(['executed', 'fully_executed']);

const RAW_AGREEMENT_FIELDS = new Set([
  'agreementbody',
  'contractbody',
  'financialtermstext',
  'privilegednegotiationnotes',
  'rawagreement',
  'rawagreementbody',
  'rawclinicaltrialagreement',
  'rawcontract',
  'rawcontractbody',
  'sourcedocumentbody',
  'sponsorconfidentialterms',
  'verbatimagreementtext',
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

function assertNoRawAgreementContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAgreementContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_AGREEMENT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw agreement content field is not allowed at ${path}.${key}`);
    }
    assertNoRawAgreementContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAgreementContent(input ?? {});
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

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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
    !hasAuthorityPermission(input?.authority, 'manage_trial_agreements') &&
      !hasAuthorityPermission(input?.authority, 'govern') &&
      !hasAuthorityPermission(input?.authority, 'write'),
    'clinical_trial_agreement_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAgreementMetadata(input, reasons) {
  const agreement = input?.agreement;
  addReason(reasons, !hasText(agreement?.agreementRef), 'agreement_ref_absent');
  addReason(reasons, !hasText(agreement?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(agreement?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(agreement?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(agreement?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(agreement?.version), 'agreement_version_absent');
  addReason(reasons, !isDigest(agreement?.agreementHash), 'agreement_hash_invalid');
  addReason(reasons, !hasText(agreement?.intakeReceiptId), 'agreement_intake_receipt_absent');
}

function evaluateExecution(input, reasons) {
  const execution = input?.agreement?.execution;
  addReason(
    reasons,
    execution?.executed !== true || !EXECUTED_STATES.has(execution?.executionState),
    'agreement_not_fully_executed',
  );
  addReason(reasons, !hasText(execution?.siteSignatoryDid), 'site_signatory_absent');
  addReason(reasons, !hasText(execution?.sponsorSignatoryRef), 'sponsor_signatory_absent');
  addReason(reasons, !isDigest(execution?.legalApprovalHash), 'legal_approval_hash_invalid');
  addReason(reasons, !isDigest(execution?.financeApprovalHash), 'finance_approval_hash_invalid');
  addReason(reasons, !isDigest(execution?.qualityApprovalHash), 'quality_approval_hash_invalid');
  addReason(reasons, !isDigest(execution?.piAcknowledgementHash), 'pi_acknowledgement_hash_invalid');
  addReason(reasons, !isDigest(execution?.siteSignatureHash), 'site_signature_hash_invalid');
  addReason(reasons, !isDigest(execution?.sponsorSignatureHash), 'sponsor_signature_hash_invalid');
  addReason(reasons, hlcTuple(execution?.executedAtHlc) === null, 'agreement_execution_time_invalid');
  addReason(reasons, hlcTuple(execution?.effectiveAtHlc) === null, 'agreement_effective_time_invalid');
  addReason(
    reasons,
    hlcTuple(execution?.effectiveAtHlc) !== null &&
      hlcTuple(execution?.executedAtHlc) !== null &&
      !hlcAfterOrEqual(execution.effectiveAtHlc, execution.executedAtHlc),
    'agreement_effective_before_execution',
  );
}

function reviewDimensionMap(input) {
  const dimensions = Array.isArray(input?.reviewDimensions) ? input.reviewDimensions : [];
  const byDimension = new Map();
  for (const item of dimensions) {
    if (hasText(item?.dimension) && !byDimension.has(item.dimension)) {
      byDimension.set(item.dimension, item);
    }
  }
  return byDimension;
}

function evaluateReviewDimension(item, reasons) {
  const dimension = item?.dimension ?? 'unknown';
  addReason(reasons, !REQUIRED_DIMENSION_SET.has(item?.dimension), `agreement_review_dimension_invalid:${dimension}`);
  addReason(reasons, !REVIEW_STATUSES.has(item?.status), `agreement_review_dimension_status_invalid:${dimension}`);
  addReason(reasons, !hasText(item?.ownerRole), `agreement_review_dimension_owner_absent:${dimension}`);
  addReason(reasons, !isDigest(item?.obligationHash), `agreement_review_dimension_obligation_hash_invalid:${dimension}`);
  addReason(reasons, !isDigest(item?.evidenceHash), `agreement_review_dimension_evidence_hash_invalid:${dimension}`);
  addReason(reasons, !['low', 'medium', 'high', 'critical'].includes(item?.riskLevel), `agreement_review_dimension_risk_invalid:${dimension}`);

  if (item?.status === 'accepted_with_conditions') {
    addReason(reasons, !hasText(item?.conditionRef), `conditional_agreement_dimension_condition_ref_absent:${dimension}`);
    addReason(reasons, !isDigest(item?.conditionEvidenceHash), `conditional_agreement_dimension_evidence_invalid:${dimension}`);
    addReason(reasons, !hasText(item?.conditionAcceptedByDid), `conditional_agreement_dimension_acceptor_absent:${dimension}`);
  }

  const unresolvedRefs = sortedTextList(item?.unresolvedIssueRefs);
  addReason(reasons, item?.status === 'accepted' && unresolvedRefs.length > 0, `accepted_agreement_dimension_has_unresolved_issue:${dimension}`);
}

function evaluateReviewDimensions(input, reasons) {
  const byDimension = reviewDimensionMap(input);
  addReason(reasons, byDimension.size === 0, 'agreement_review_dimensions_absent');
  for (const dimension of REQUIRED_REVIEW_DIMENSIONS) {
    addReason(reasons, !byDimension.has(dimension), `required_agreement_review_dimension_missing:${dimension}`);
  }
  for (const item of byDimension.values()) {
    evaluateReviewDimension(item, reasons);
  }
}

function evaluateIssue(issue, reviewedAtHlc, reasons) {
  const issueRef = issue?.issueRef ?? 'unknown';
  addReason(reasons, !hasText(issue?.issueRef), 'agreement_issue_ref_absent');
  addReason(reasons, !ISSUE_SEVERITY_SET.has(issue?.severity), `agreement_issue_severity_invalid:${issueRef}`);
  addReason(reasons, !hasText(issue?.status), `agreement_issue_status_absent:${issueRef}`);
  addReason(reasons, !hasText(issue?.ownerDid), `agreement_issue_owner_absent:${issueRef}`);
  addReason(reasons, !isDigest(issue?.mitigationHash), `agreement_issue_mitigation_invalid:${issueRef}`);
  addReason(reasons, hlcTuple(issue?.targetResolutionHlc) === null, `agreement_issue_target_time_invalid:${issueRef}`);
  addReason(
    reasons,
    hlcTuple(issue?.targetResolutionHlc) !== null &&
      hlcTuple(reviewedAtHlc) !== null &&
      !hlcAfterOrEqual(issue.targetResolutionHlc, reviewedAtHlc),
    `agreement_issue_target_before_review:${issueRef}`,
  );
  addReason(
    reasons,
    issue?.severity === 'critical' && !ISSUE_RESOLVED_STATUSES.has(issue?.status),
    `critical_agreement_issue_unresolved:${issueRef}`,
  );
}

function evaluateIssues(input, reasons) {
  const issues = Array.isArray(input?.issues) ? input.issues : [];
  for (const issue of issues) {
    evaluateIssue(issue, input?.review?.reviewedAtHlc, reasons);
  }
}

function evaluateAiReview(review, reasons) {
  const aiReview = review?.aiReview;
  addReason(reasons, aiReview?.completed !== true, 'ai_review_incomplete');
  addReason(reasons, aiReview?.advisoryOnly !== true, 'ai_review_must_be_advisory');
  addReason(reasons, aiReview?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(aiReview?.outputHash), 'ai_review_output_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(aiReview?.evidenceUsedHashes) ||
      aiReview.evidenceUsedHashes.length === 0 ||
      aiReview.evidenceUsedHashes.some((hash) => !isDigest(hash)),
    'ai_review_evidence_hash_invalid',
  );
}

function evaluateDecisionForum(review, reasons) {
  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true || forum?.state !== 'approved', 'decision_forum_unverified');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function evaluateReviewGovernance(input, reasons) {
  const review = input?.review;
  addReason(reasons, !hasText(review?.reviewRef), 'agreement_review_ref_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'agreement_review_time_invalid');
  addReason(reasons, !hasText(review?.legalReviewerDid), 'legal_reviewer_absent');
  addReason(reasons, !hasText(review?.financialReviewerDid), 'financial_reviewer_absent');
  addReason(reasons, !hasText(review?.qualityReviewerDid), 'quality_reviewer_absent');
  addReason(reasons, !hasText(review?.principalInvestigatorDid), 'principal_investigator_absent');
  evaluateAiReview(review, reasons);
  evaluateDecisionForum(review, reasons);
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(
    reasons,
    hlcTuple(input?.agreement?.execution?.executedAtHlc) !== null &&
      hlcTuple(review?.reviewedAtHlc) !== null &&
      !hlcAfterOrEqual(input.agreement.execution.executedAtHlc, review.reviewedAtHlc),
    'agreement_executed_before_review_complete',
  );
}

function evaluateLaunchDependency(input, reasons) {
  const launchDependency = input?.launchDependency;
  addReason(reasons, !hasText(launchDependency?.protocolLaunchGateRef), 'launch_gate_ref_absent');
  addReason(reasons, launchDependency?.requiresExecutedAgreement !== true, 'launch_requires_executed_agreement_invalid');
  addReason(reasons, !isDigest(launchDependency?.launchGateCheckHash), 'launch_gate_check_hash_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function openIssueSummary(issues) {
  const summary = { critical: 0, major: 0, minor: 0 };
  for (const issue of Array.isArray(issues) ? issues : []) {
    if (ISSUE_SEVERITY_SET.has(issue?.severity) && issue?.status !== 'closed' && issue?.status !== 'resolved') {
      summary[issue.severity] += 1;
    }
  }
  return summary;
}

function agreementReviewId(input) {
  return `cmpcta_${sha256Hex({
    agreementHash: input?.agreement?.agreementHash ?? null,
    agreementRef: input?.agreement?.agreementRef ?? null,
    protocolRef: input?.agreement?.protocolRef ?? null,
    reviewRef: input?.review?.reviewRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function coveredReviewDimensions(input) {
  return uniqueSorted(
    [...reviewDimensionMap(input).keys()].filter((dimension) => REQUIRED_DIMENSION_SET.has(dimension)),
  );
}

function requiredLaunchEvidenceRefs(input) {
  return sortedTextList([
    input?.review?.reviewRef,
    input?.launchDependency?.protocolLaunchGateRef,
    input?.agreement?.intakeReceiptId,
  ]);
}

function buildAgreementReview(input, status, receiptId = null) {
  const coveredDimensions = coveredReviewDimensions(input);
  const execution = input?.agreement?.execution;

  return {
    schema: 'cybermedica.clinical_trial_agreement_review.v1',
    reviewId: agreementReviewId(input),
    tenantId: input?.tenantId ?? null,
    agreementRef: input?.agreement?.agreementRef ?? null,
    protocolRef: input?.agreement?.protocolRef ?? null,
    studyRef: input?.agreement?.studyRef ?? null,
    siteRef: input?.agreement?.siteRef ?? null,
    sponsorRef: input?.agreement?.sponsorRef ?? null,
    croRef: input?.agreement?.croRef ?? null,
    agreementVersion: input?.agreement?.version ?? null,
    status,
    executionState: execution?.executionState ?? null,
    executed: execution?.executed === true,
    executedAtHlc: execution?.executedAtHlc ?? null,
    effectiveAtHlc: execution?.effectiveAtHlc ?? null,
    launchDependencySatisfied: status === 'launch_ready',
    requiredLaunchEvidenceRefs: requiredLaunchEvidenceRefs(input),
    coveredReviewDimensions: coveredDimensions,
    policy10CoverageBasisPoints: basisPoints(coveredDimensions.length, REQUIRED_REVIEW_DIMENSIONS.length),
    openIssueSummary: openIssueSummary(input?.issues),
    decisionForumDecisionId: input?.review?.decisionForum?.decisionId ?? null,
    decisionForumWorkflowReceiptId: input?.review?.decisionForum?.workflowReceiptId ?? null,
    aiFinalAuthority: input?.review?.aiReview?.finalAuthority === true,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createAgreementReceipt(input, agreementReview, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'clinical_trial_agreement_review',
    artifactVersion: `${agreementReview.agreementRef}@${agreementReview.agreementVersion}`,
    classification: 'clinical_trial_agreement_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.agreement.execution.executedAtHlc,
    sensitivityTags: ['clinical_trial_agreement', 'metadata_only', 'trial_launch'],
    sourceSystem: 'cybermedica.clinical_trial_agreements',
    tenantId: input.tenantId,
  });
}

export function evaluateClinicalTrialAgreementReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAgreementMetadata(input, reasons);
  evaluateReviewGovernance(input, reasons);
  evaluateReviewDimensions(input, reasons);
  evaluateIssues(input, reasons);
  evaluateExecution(input, reasons);
  evaluateLaunchDependency(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.clinical_trial_agreement_review_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      agreementReview: buildAgreementReview(input, 'blocked'),
      receipt: null,
    };
  }

  const agreementReview = buildAgreementReview(input, 'launch_ready');
  const artifactHash = sha256Hex({
    agreementHash: input.agreement.agreementHash,
    agreementRef: agreementReview.agreementRef,
    coveredReviewDimensions: agreementReview.coveredReviewDimensions,
    decisionForumDecisionId: agreementReview.decisionForumDecisionId,
    executionState: agreementReview.executionState,
    financeApprovalHash: input.agreement.execution.financeApprovalHash,
    issueSummary: agreementReview.openIssueSummary,
    legalApprovalHash: input.agreement.execution.legalApprovalHash,
    launchEvidenceRefs: agreementReview.requiredLaunchEvidenceRefs,
    piAcknowledgementHash: input.agreement.execution.piAcknowledgementHash,
    protocolRef: agreementReview.protocolRef,
    qualityApprovalHash: input.agreement.execution.qualityApprovalHash,
    reviewId: agreementReview.reviewId,
    siteSignatureHash: input.agreement.execution.siteSignatureHash,
    sponsorSignatureHash: input.agreement.execution.sponsorSignatureHash,
    tenantId: input.tenantId,
  });
  const receipt = createAgreementReceipt(input, agreementReview, artifactHash);

  return {
    schema: 'cybermedica.clinical_trial_agreement_review_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    agreementReview: {
      ...agreementReview,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
