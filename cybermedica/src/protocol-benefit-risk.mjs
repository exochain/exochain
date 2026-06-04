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
const BENEFIT_RISK_SCHEMA = 'cybermedica.protocol_benefit_risk.v1';
const DECISION_SCHEMA = 'cybermedica.protocol_benefit_risk_decision.v1';
const REQUIRED_PERMISSION = 'assess_protocol_benefit_risk';

const REQUIRED_BENEFIT_DOMAINS = Object.freeze([
  'data_integrity_value',
  'participant_rights',
  'participant_safety',
  'participant_wellbeing',
  'post_termination_support',
  'protocol_fit',
  'risk_mitigation',
  'scientific_social_value',
]);

const REQUIRED_PROTECTION_DOMAINS = Object.freeze([
  'claims_exposure',
  'emergency_waiver_controls',
  'insurance_coverage',
  'malpractice_negligence',
  'non_waiver_legal_rights',
  'participant_compensation',
  'privacy_minimization',
  'recruitment_non_coercion',
]);

const BENEFIT_DOMAINS = new Set(REQUIRED_BENEFIT_DOMAINS);
const PROTECTION_DOMAINS = new Set(REQUIRED_PROTECTION_DOMAINS);
const POLICY_STATUSES = new Set(['active']);
const BENEFIT_STATUSES = new Set(['supported', 'supported_with_conditions', 'unsupported', 'deferred']);
const PROTECTION_STATUSES = new Set(['ready', 'ready_with_conditions', 'not_ready', 'deferred']);
const RESIDUAL_RISK_STATUSES = new Set(['accepted', 'accepted_with_conditions', 'monitoring_required', 'unacceptable']);

const RAW_BENEFIT_RISK_FIELDS = new Set([
  'benefitnarrative',
  'clinicalnarrative',
  'directidentifier',
  'freeformbenefittext',
  'freetextbenefitnotes',
  'medicalhistory',
  'participantdetails',
  'participantstory',
  'patienthistory',
  'protocolbody',
  'protocoltext',
  'rawbenefit',
  'rawclinicalcontent',
  'rawparticipant',
  'rawpayload',
  'rawprotocol',
  'rawrisk',
  'risknarrative',
  'sourcedocumentbody',
]);

const SECRET_BENEFIT_RISK_FIELDS = new Set([
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
  'servicetoken',
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

function isNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawBenefitRiskContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawBenefitRiskContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_BENEFIT_RISK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw protocol benefit-risk content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_BENEFIT_RISK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol benefit-risk secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawBenefitRiskContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawBenefitRiskContent(input ?? {});
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

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function evaluateRequiredSet(actual, expected, supported, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !supported.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function coverageBasisPoints(coveredCount, requiredCount) {
  return Number((BigInt(coveredCount) * 10_000n) / BigInt(requiredCount));
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
    'protocol_benefit_risk_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'benefit_risk_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'benefit_risk_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'benefit_risk_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'benefit_risk_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'benefit_risk_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'benefit_risk_policy_evaluation_time_invalid');
  addReason(reasons, !isBasisPoints(policy?.minimumBenefitCoverageBasisPoints), 'minimum_benefit_coverage_basis_points_invalid');
  addReason(reasons, !isBasisPoints(policy?.minimumProtectionCoverageBasisPoints), 'minimum_protection_coverage_basis_points_invalid');

  const requiredBenefitDomains = sortedTextList(policy?.requiredBenefitDomains);
  const requiredProtectionDomains = sortedTextList(policy?.requiredProtectionDomains);
  evaluateRequiredSet(
    requiredBenefitDomains,
    REQUIRED_BENEFIT_DOMAINS,
    BENEFIT_DOMAINS,
    'benefit_risk_policy_benefit_domain_missing',
    'benefit_risk_policy_benefit_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredProtectionDomains,
    REQUIRED_PROTECTION_DOMAINS,
    PROTECTION_DOMAINS,
    'benefit_risk_policy_protection_domain_missing',
    'benefit_risk_policy_protection_domain_unsupported',
    reasons,
  );

  return {
    requiredBenefitDomains: requiredBenefitDomains.length > 0 ? requiredBenefitDomains : [...REQUIRED_BENEFIT_DOMAINS],
    requiredProtectionDomains: requiredProtectionDomains.length > 0 ? requiredProtectionDomains : [...REQUIRED_PROTECTION_DOMAINS],
  };
}

function evaluateProtocolContext(context, policy, reasons) {
  addReason(reasons, !hasText(context?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(context?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(context?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(context?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(context?.croRef), 'cro_ref_absent');
  addReason(reasons, !isDigest(context?.protocolVersionHash), 'protocol_version_hash_invalid');
  addReason(reasons, !isDigest(context?.populationFitHash), 'population_fit_hash_invalid');
  addReason(reasons, !isDigest(context?.benefitRiskMatrixHash), 'benefit_risk_matrix_hash_invalid');
  addReason(reasons, context?.metadataOnly !== true, 'protocol_context_metadata_boundary_invalid');
  addReason(reasons, context?.protectedContentExcluded !== true, 'protocol_context_protected_boundary_invalid');
  addReason(reasons, hlcTuple(context?.createdAtHlc) === null, 'protocol_created_time_invalid');
  addReason(reasons, hlcTuple(context?.approvedAtHlc) === null, 'protocol_approved_time_invalid');
  addReason(reasons, !hlcBefore(context?.createdAtHlc, context?.approvedAtHlc), 'protocol_approval_order_invalid');
  addReason(reasons, !hlcAfter(context?.approvedAtHlc, policy?.evaluatedAtHlc), 'protocol_approved_before_policy_evaluation');
}

function benefitDomainIdentity(row) {
  return hasText(row?.domain) ? row.domain : 'unknown_benefit_domain';
}

function protectionDomainIdentity(row) {
  return hasText(row?.domain) ? row.domain : 'unknown_protection_domain';
}

function evaluateBenefitDomain(row, context, reasons) {
  const domain = benefitDomainIdentity(row);
  const ready = row?.status === 'supported' || row?.status === 'supported_with_conditions';

  addReason(reasons, !BENEFIT_DOMAINS.has(row?.domain), `benefit_domain_invalid:${domain}`);
  addReason(reasons, !BENEFIT_STATUSES.has(row?.status), `benefit_domain_status_invalid:${domain}`);
  addReason(reasons, BENEFIT_STATUSES.has(row?.status) && !ready, `benefit_domain_not_supported:${domain}`);
  addReason(reasons, !isDigest(row?.evidenceHash), `benefit_domain_evidence_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.benefitStatementHash), `benefit_statement_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.participantRelevanceHash), `participant_relevance_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.limitationHash), `benefit_limitation_hash_invalid:${domain}`);
  addReason(reasons, !hasText(row?.ownerDid), `benefit_domain_owner_absent:${domain}`);
  addReason(reasons, row?.metadataOnly !== true, `benefit_domain_metadata_boundary_invalid:${domain}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `benefit_domain_protected_boundary_invalid:${domain}`);
  addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `benefit_domain_review_time_invalid:${domain}`);
  addReason(
    reasons,
    hlcBefore(row?.reviewedAtHlc, context?.approvedAtHlc),
    `benefit_domain_review_before_protocol_approval:${domain}`,
  );

  if (row?.status === 'supported_with_conditions') {
    addReason(reasons, !hasText(row?.conditionRef), `conditional_benefit_condition_ref_absent:${domain}`);
    addReason(reasons, !isDigest(row?.mitigationHash), `conditional_benefit_mitigation_invalid:${domain}`);
  }

  return {
    conditionRef: row?.conditionRef,
    domain,
    ready,
  };
}

function evaluateBenefitDomains(rows, requiredBenefitDomains, context, reasons) {
  const benefitRows = Array.isArray(rows) ? rows : [];
  addReason(reasons, benefitRows.length === 0, 'benefit_domain_collection_absent');

  const summaries = benefitRows.map((row) => evaluateBenefitDomain(row, context, reasons));
  const benefitDomainsCovered = uniqueSorted(
    summaries.filter((summary) => summary.ready && BENEFIT_DOMAINS.has(summary.domain)).map((summary) => summary.domain),
  );

  for (const domain of requiredBenefitDomains) {
    addReason(reasons, !benefitDomainsCovered.includes(domain), `required_benefit_domain_missing:${domain}`);
  }

  return {
    benefitCoverageBasisPoints: coverageBasisPoints(benefitDomainsCovered.length, REQUIRED_BENEFIT_DOMAINS.length),
    benefitDomainsCovered,
    conditionRefs: uniqueSorted(summaries.map((summary) => summary.conditionRef)),
  };
}

function evaluateProtectionDomain(row, context, reasons) {
  const domain = protectionDomainIdentity(row);
  const ready = row?.status === 'ready' || row?.status === 'ready_with_conditions';

  addReason(reasons, !PROTECTION_DOMAINS.has(row?.domain), `protection_domain_invalid:${domain}`);
  addReason(reasons, !PROTECTION_STATUSES.has(row?.status), `protection_domain_status_invalid:${domain}`);
  addReason(reasons, PROTECTION_STATUSES.has(row?.status) && !ready, `protection_domain_not_ready:${domain}`);
  addReason(reasons, !isDigest(row?.evidenceHash), `protection_domain_evidence_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.controlHash), `protection_domain_control_hash_invalid:${domain}`);
  addReason(reasons, !hasText(row?.ownerDid), `protection_domain_owner_absent:${domain}`);
  addReason(reasons, row?.metadataOnly !== true, `protection_domain_metadata_boundary_invalid:${domain}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `protection_domain_protected_boundary_invalid:${domain}`);
  addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `protection_domain_review_time_invalid:${domain}`);
  addReason(
    reasons,
    hlcBefore(row?.reviewedAtHlc, context?.approvedAtHlc),
    `protection_domain_review_before_protocol_approval:${domain}`,
  );

  if (row?.status === 'ready_with_conditions') {
    addReason(reasons, !hasText(row?.conditionRef), `conditional_protection_condition_ref_absent:${domain}`);
    addReason(reasons, !isDigest(row?.mitigationHash), `conditional_protection_mitigation_invalid:${domain}`);
  }

  return {
    conditionRef: row?.conditionRef,
    domain,
    ready,
  };
}

function evaluateProtectionDomains(rows, requiredProtectionDomains, context, reasons) {
  const protectionRows = Array.isArray(rows) ? rows : [];
  addReason(reasons, protectionRows.length === 0, 'protection_domain_collection_absent');

  const summaries = protectionRows.map((row) => evaluateProtectionDomain(row, context, reasons));
  const protectionDomainsCovered = uniqueSorted(
    summaries
      .filter((summary) => summary.ready && PROTECTION_DOMAINS.has(summary.domain))
      .map((summary) => summary.domain),
  );

  for (const domain of requiredProtectionDomains) {
    addReason(reasons, !protectionDomainsCovered.includes(domain), `required_protection_domain_missing:${domain}`);
  }

  return {
    conditionRefs: uniqueSorted(summaries.map((summary) => summary.conditionRef)),
    protectionCoverageBasisPoints: coverageBasisPoints(protectionDomainsCovered.length, REQUIRED_PROTECTION_DOMAINS.length),
    protectionDomainsCovered,
  };
}

function evaluateResidualRisk(review, context, reasons) {
  addReason(reasons, !hasText(review?.reviewRef), 'benefit_risk_review_ref_absent');
  addReason(reasons, !RESIDUAL_RISK_STATUSES.has(review?.residualRiskStatus), 'residual_risk_status_invalid');
  addReason(reasons, review?.residualRiskStatus === 'unacceptable', 'residual_risk_unacceptable');
  addReason(reasons, !isNonNegativeInteger(review?.criticalResidualRiskCount), 'critical_residual_risk_count_invalid');
  addReason(reasons, !isNonNegativeInteger(review?.highResidualRiskCount), 'high_residual_risk_count_invalid');
  addReason(reasons, !isNonNegativeInteger(review?.unmitigatedRiskCount), 'unmitigated_risk_count_invalid');
  addReason(reasons, Number.isSafeInteger(review?.criticalResidualRiskCount) && review.criticalResidualRiskCount > 0, 'critical_residual_risk_open');
  addReason(reasons, Number.isSafeInteger(review?.unmitigatedRiskCount) && review.unmitigatedRiskCount > 0, 'unmitigated_risk_open');
  addReason(
    reasons,
    Number.isSafeInteger(review?.highResidualRiskCount) &&
      review.highResidualRiskCount > 0 &&
      sortedTextList(review?.highRiskConditionRefs).length === 0,
    'high_residual_risk_condition_refs_absent',
  );
  addReason(reasons, !hasText(review?.acceptedByDid), 'benefit_risk_acceptance_actor_absent');
  addReason(reasons, !isDigest(review?.acceptanceRationaleHash), 'benefit_risk_acceptance_rationale_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'benefit_risk_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, context?.approvedAtHlc), 'benefit_risk_review_before_protocol_approval');
  addReason(reasons, review?.metadataOnly !== true, 'benefit_risk_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'benefit_risk_review_protected_boundary_invalid');

  return sortedTextList(review?.highRiskConditionRefs);
}

function evaluateDependencies(dependencies, reasons) {
  addReason(reasons, !hasText(dependencies?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, !hasText(dependencies?.startupRiskAssessmentRef), 'startup_risk_assessment_ref_absent');
  addReason(reasons, !hasText(dependencies?.insuranceClaimsReadinessRef), 'insurance_claims_readiness_ref_absent');
  addReason(reasons, !hasText(dependencies?.consentMaterialsRef), 'consent_materials_ref_absent');
  addReason(reasons, !hasText(dependencies?.independentEthicsApprovalRef), 'independent_ethics_approval_ref_absent');
  addReason(
    reasons,
    !Array.isArray(dependencies?.evidenceHashes) ||
      dependencies.evidenceHashes.length === 0 ||
      dependencies.evidenceHashes.some((hash) => !isDigest(hash)),
    'benefit_risk_dependency_evidence_hash_invalid',
  );
  addReason(reasons, dependencies?.metadataOnly !== true, 'benefit_risk_dependency_metadata_boundary_invalid');
}

function evaluateHumanGovernance(review, reasons) {
  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function buildProtocolBenefitRisk(input, benefitSummary, protectionSummary, residualConditionRefs, reasons) {
  const permitted = reasons.length === 0;
  const conditionRefs = uniqueSorted([
    ...benefitSummary.conditionRefs,
    ...protectionSummary.conditionRefs,
    ...residualConditionRefs,
  ]);
  const acceptedWithConditions =
    permitted &&
    (conditionRefs.length > 0 ||
      input?.residualRiskReview?.residualRiskStatus === 'accepted_with_conditions' ||
      input?.residualRiskReview?.highResidualRiskCount > 0);

  const material = {
    schema: BENEFIT_RISK_SCHEMA,
    tenantId: input?.tenantId ?? '',
    policyRef: input?.benefitRiskPolicy?.policyRef ?? '',
    protocolRef: input?.protocolContext?.protocolRef ?? '',
    studyRef: input?.protocolContext?.studyRef ?? '',
    siteRef: input?.protocolContext?.siteRef ?? '',
    sponsorRef: input?.protocolContext?.sponsorRef ?? '',
    croRef: input?.protocolContext?.croRef ?? '',
    evaluatedAtHlc: input?.benefitRiskPolicy?.evaluatedAtHlc ?? null,
    protocolApprovedAtHlc: input?.protocolContext?.approvedAtHlc ?? null,
    reviewedAtHlc: input?.residualRiskReview?.reviewedAtHlc ?? null,
    benefitCoverageBasisPoints: benefitSummary.benefitCoverageBasisPoints,
    protectionCoverageBasisPoints: protectionSummary.protectionCoverageBasisPoints,
    benefitDomainsCovered: benefitSummary.benefitDomainsCovered,
    protectionDomainsCovered: protectionSummary.protectionDomainsCovered,
    residualRiskStatus: input?.residualRiskReview?.residualRiskStatus ?? 'unclassified',
    highResidualRiskCount: Number.isSafeInteger(input?.residualRiskReview?.highResidualRiskCount)
      ? input.residualRiskReview.highResidualRiskCount
      : null,
    criticalResidualRiskCount: Number.isSafeInteger(input?.residualRiskReview?.criticalResidualRiskCount)
      ? input.residualRiskReview.criticalResidualRiskCount
      : null,
    unmitigatedRiskCount: Number.isSafeInteger(input?.residualRiskReview?.unmitigatedRiskCount)
      ? input.residualRiskReview.unmitigatedRiskCount
      : null,
    conditionRefs,
    dependencyRefs: {
      consentMaterialsRef: input?.dependencies?.consentMaterialsRef ?? '',
      independentEthicsApprovalRef: input?.dependencies?.independentEthicsApprovalRef ?? '',
      insuranceClaimsReadinessRef: input?.dependencies?.insuranceClaimsReadinessRef ?? '',
      protocolFeasibilityRef: input?.dependencies?.protocolFeasibilityRef ?? '',
      startupRiskAssessmentRef: input?.dependencies?.startupRiskAssessmentRef ?? '',
    },
  };

  return {
    ...material,
    acceptanceId: `benefit_risk_${sha256Hex(material).slice(0, 32)}`,
    acceptanceStatus: permitted
      ? acceptedWithConditions
        ? 'benefit_risk_accepted_with_conditions'
        : 'benefit_risk_accepted'
      : 'benefit_risk_not_accepted',
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true || input?.actor?.kind === 'ai_agent',
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createBenefitRiskReceipt(input, protocolBenefitRisk) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did,
    artifactHash: sha256Hex(protocolBenefitRisk),
    artifactType: 'protocol_benefit_risk',
    artifactVersion: '1',
    classification: 'sponsor-cro-confidential-metadata',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.residualRiskReview?.reviewedAtHlc,
    sensitivityTags: ['benefit_risk', 'clinical_research', 'metadata_only', 'participant_protection'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input?.tenantId,
  });
}

export function evaluateProtocolBenefitRisk(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluatePolicy(input?.benefitRiskPolicy, reasons);
  evaluateProtocolContext(input?.protocolContext, input?.benefitRiskPolicy, reasons);
  const benefitSummary = evaluateBenefitDomains(input?.benefitDomains, policy.requiredBenefitDomains, input?.protocolContext, reasons);
  const protectionSummary = evaluateProtectionDomains(
    input?.protectionDomains,
    policy.requiredProtectionDomains,
    input?.protocolContext,
    reasons,
  );
  const residualConditionRefs = evaluateResidualRisk(input?.residualRiskReview, input?.protocolContext, reasons);
  evaluateDependencies(input?.dependencies, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const protocolBenefitRisk = buildProtocolBenefitRisk(input, benefitSummary, protectionSummary, residualConditionRefs, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    protocolBenefitRisk,
    receipt: permitted ? createBenefitRiskReceipt(input, protocolBenefitRisk) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
