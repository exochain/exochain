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
const CURRENCY_CODE = /^[A-Z]{3}$/u;
const BUDGET_SCHEMA = 'cybermedica.study_budget_feasibility.v1';
const DECISION_SCHEMA = 'cybermedica.study_budget_feasibility_decision.v1';

const REQUIRED_COST_DOMAINS = Object.freeze([
  'data_management_systems',
  'facility_and_equipment',
  'investigational_product_handling',
  'lab_and_imaging',
  'monitoring_and_audit',
  'participant_reimbursement',
  'regulatory_ethics',
  'staff_time',
  'training_startup',
  'vendor_subcontractor',
]);

const REQUIRED_REVIEW_DOMAINS = Object.freeze([
  'cashflow',
  'contract_alignment',
  'contingency',
  'cost_domain_coverage',
  'finance_approval',
  'resource_fit',
  'sponsor_payment_terms',
]);

const COST_DOMAINS = new Set(REQUIRED_COST_DOMAINS);
const REVIEW_DOMAINS = new Set(REQUIRED_REVIEW_DOMAINS);
const POLICY_STATUSES = new Set(['active']);
const BUDGET_STATUSES = new Set(['approved', 'approved_with_conditions']);
const COST_DOMAIN_STATUSES = new Set(['covered', 'covered_with_conditions', 'deferred', 'not_covered']);
const REQUIRED_PERMISSION = 'assess_budget_feasibility';

const RAW_BUDGET_FIELDS = new Set([
  'bankaccount',
  'bankaccountnumber',
  'contractbody',
  'directidentifier',
  'freetextbudgetnotes',
  'invoicebody',
  'negotiatedterms',
  'participantname',
  'patientname',
  'rawbudget',
  'rawbudgetbody',
  'rawcontract',
  'rawfinanceworksheet',
  'rawinvoice',
  'rawpayload',
  'sponsorbudgetbody',
  'sponsorbudgettext',
  'sourcedocumentbody',
  'taxid',
  'wireinstructions',
]);

const SECRET_BUDGET_FIELDS = new Set([
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

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawBudgetContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawBudgetContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_BUDGET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw study budget content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_BUDGET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`study budget secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawBudgetContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawBudgetContent(input ?? {});
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

function calculateMarginBasisPoints(sponsorBudgetMinorUnits, totalCostMinorUnits) {
  if (!isSafePositiveInteger(sponsorBudgetMinorUnits) || !Number.isSafeInteger(totalCostMinorUnits)) {
    return null;
  }
  return Number((BigInt(sponsorBudgetMinorUnits - totalCostMinorUnits) * 10_000n) / BigInt(sponsorBudgetMinorUnits));
}

function costDomainIdentity(domainReview) {
  return hasText(domainReview?.domain) ? domainReview.domain : 'unknown';
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
    'budget_feasibility_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateBudgetPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'budget_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'budget_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'budget_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'budget_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'budget_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'budget_policy_evaluation_time_invalid');
  addReason(reasons, !isBasisPoints(policy?.minimumContingencyBasisPoints), 'minimum_contingency_basis_points_invalid');
  addReason(reasons, !isBasisPoints(policy?.minimumMarginBasisPoints), 'minimum_margin_basis_points_invalid');
  addReason(reasons, !isBasisPoints(policy?.maximumDomainVarianceBasisPoints), 'maximum_domain_variance_basis_points_invalid');

  const requiredCostDomains = sortedTextList(policy?.requiredCostDomains);
  const requiredReviewDomains = sortedTextList(policy?.requiredReviewDomains);
  evaluateRequiredSet(
    requiredCostDomains,
    REQUIRED_COST_DOMAINS,
    COST_DOMAINS,
    'budget_policy_cost_domain_missing',
    'budget_policy_cost_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredReviewDomains,
    REQUIRED_REVIEW_DOMAINS,
    REVIEW_DOMAINS,
    'budget_policy_review_domain_missing',
    'budget_policy_review_domain_unsupported',
    reasons,
  );

  return {
    requiredCostDomains: requiredCostDomains.length > 0 ? requiredCostDomains : [...REQUIRED_COST_DOMAINS],
    requiredReviewDomains: requiredReviewDomains.length > 0 ? requiredReviewDomains : [...REQUIRED_REVIEW_DOMAINS],
  };
}

function evaluateStudyBudget(budget, policy, reasons) {
  addReason(reasons, !hasText(budget?.budgetRef), 'budget_ref_absent');
  addReason(reasons, !hasText(budget?.protocolRef), 'budget_protocol_ref_absent');
  addReason(reasons, !hasText(budget?.siteRef), 'budget_site_ref_absent');
  addReason(reasons, !hasText(budget?.sponsorRef), 'budget_sponsor_ref_absent');
  addReason(reasons, !hasText(budget?.croRef), 'budget_cro_ref_absent');
  addReason(reasons, !BUDGET_STATUSES.has(budget?.status), 'budget_status_not_approved');
  addReason(reasons, !hasText(budget?.currencyCode) || !CURRENCY_CODE.test(budget.currencyCode), 'currency_code_invalid');
  addReason(reasons, !isSafePositiveInteger(budget?.sponsorBudgetMinorUnits), 'sponsor_budget_minor_units_invalid');
  addReason(reasons, !isSafePositiveInteger(budget?.totalCostMinorUnits), 'total_cost_minor_units_invalid');
  addReason(reasons, !isBasisPoints(budget?.contingencyBasisPoints), 'contingency_basis_points_invalid');
  addReason(reasons, !isDigest(budget?.budgetVersionHash), 'budget_version_hash_invalid');
  addReason(reasons, !isDigest(budget?.scheduleOfEventsHash), 'schedule_of_events_hash_invalid');
  addReason(reasons, !isDigest(budget?.coverageMatrixHash), 'budget_coverage_matrix_hash_invalid');
  addReason(reasons, budget?.metadataOnly !== true, 'budget_metadata_boundary_invalid');
  addReason(reasons, budget?.protectedContentExcluded !== true, 'budget_protected_boundary_invalid');
  addReason(reasons, hlcTuple(budget?.createdAtHlc) === null, 'budget_created_time_invalid');
  addReason(reasons, hlcTuple(budget?.approvedAtHlc) === null, 'budget_approved_time_invalid');
  addReason(reasons, !hlcBefore(budget?.createdAtHlc, budget?.approvedAtHlc), 'budget_approval_order_invalid');
  addReason(reasons, !hlcAfter(budget?.approvedAtHlc, policy?.evaluatedAtHlc), 'budget_approved_before_policy_evaluation');

  const margin = calculateMarginBasisPoints(budget?.sponsorBudgetMinorUnits, budget?.totalCostMinorUnits);
  addReason(
    reasons,
    isSafePositiveInteger(budget?.sponsorBudgetMinorUnits) &&
      isSafePositiveInteger(budget?.totalCostMinorUnits) &&
      budget.totalCostMinorUnits > budget.sponsorBudgetMinorUnits,
    'budget_deficit_detected',
  );
  addReason(
    reasons,
    margin !== null && isBasisPoints(policy?.minimumMarginBasisPoints) && margin < policy.minimumMarginBasisPoints,
    'budget_margin_below_minimum',
  );
  addReason(
    reasons,
    isBasisPoints(budget?.contingencyBasisPoints) &&
      isBasisPoints(policy?.minimumContingencyBasisPoints) &&
      budget.contingencyBasisPoints < policy.minimumContingencyBasisPoints,
    'contingency_below_minimum',
  );

  return margin;
}

function evaluateCostDomain(domainReview, maximumVarianceBasisPoints, reasons) {
  const domain = costDomainIdentity(domainReview);
  const ready = domainReview?.status === 'covered' || domainReview?.status === 'covered_with_conditions';

  addReason(reasons, !COST_DOMAINS.has(domainReview?.domain), `cost_domain_invalid:${domain}`);
  addReason(reasons, !COST_DOMAIN_STATUSES.has(domainReview?.status), `cost_domain_status_invalid:${domain}`);
  addReason(reasons, COST_DOMAIN_STATUSES.has(domainReview?.status) && !ready, `cost_domain_not_ready:${domain}`);
  addReason(reasons, !isSafePositiveInteger(domainReview?.budgetMinorUnits), `cost_domain_budget_minor_units_invalid:${domain}`);
  addReason(reasons, !isDigest(domainReview?.evidenceHash), `cost_domain_evidence_invalid:${domain}`);
  addReason(reasons, !hasText(domainReview?.ownerDid), `cost_domain_owner_absent:${domain}`);
  addReason(reasons, !isDigest(domainReview?.rationaleHash), `cost_domain_rationale_invalid:${domain}`);
  addReason(reasons, !isBasisPoints(domainReview?.varianceBasisPoints), `cost_domain_variance_invalid:${domain}`);
  addReason(
    reasons,
    isBasisPoints(domainReview?.varianceBasisPoints) &&
      isBasisPoints(maximumVarianceBasisPoints) &&
      domainReview.varianceBasisPoints > maximumVarianceBasisPoints,
    `cost_domain_variance_over_limit:${domain}`,
  );
  addReason(reasons, domainReview?.metadataOnly !== true, `cost_domain_metadata_boundary_invalid:${domain}`);
  addReason(reasons, domainReview?.protectedContentExcluded !== true, `cost_domain_protected_boundary_invalid:${domain}`);

  if (domainReview?.status === 'covered_with_conditions') {
    addReason(reasons, !hasText(domainReview?.conditionRef), `conditional_cost_domain_condition_ref_absent:${domain}`);
    addReason(reasons, !isDigest(domainReview?.conditionMitigationHash), `conditional_cost_domain_mitigation_invalid:${domain}`);
  }

  return {
    domain,
    status: domainReview?.status,
    ready,
    budgetMinorUnits: domainReview?.budgetMinorUnits,
    conditionRef: domainReview?.conditionRef,
  };
}

function evaluateCostDomains(domainReviews, requiredCostDomains, budget, policy, reasons) {
  const rows = Array.isArray(domainReviews) ? domainReviews : [];
  addReason(reasons, rows.length === 0, 'cost_domain_collection_absent');

  const summaries = rows.map((row) => evaluateCostDomain(row, policy?.maximumDomainVarianceBasisPoints, reasons));
  const domainsCovered = uniqueSorted(
    summaries.filter((summary) => summary.ready && COST_DOMAINS.has(summary.domain)).map((summary) => summary.domain),
  );

  for (const domain of requiredCostDomains) {
    addReason(reasons, !domainsCovered.includes(domain), `required_cost_domain_missing:${domain}`);
  }

  const domainTotal = summaries.reduce(
    (total, summary) => (isSafePositiveInteger(summary.budgetMinorUnits) ? total + summary.budgetMinorUnits : total),
    0,
  );
  addReason(
    reasons,
    isSafePositiveInteger(budget?.totalCostMinorUnits) && domainTotal !== budget.totalCostMinorUnits,
    'cost_domain_total_mismatch',
  );

  return {
    conditionRefs: uniqueSorted(summaries.map((summary) => summary.conditionRef)),
    costCoverageBasisPoints: Number((BigInt(domainsCovered.length) * 10_000n) / BigInt(REQUIRED_COST_DOMAINS.length)),
    coveredCostDomains: domainsCovered,
    domainTotalMinorUnits: domainTotal,
  };
}

function evaluateResourcePlan(resourcePlan, reasons) {
  addReason(reasons, !isDigest(resourcePlan?.resourceNeedHash), 'resource_need_hash_invalid');
  addReason(reasons, !isDigest(resourcePlan?.staffingPlanHash), 'staffing_plan_hash_invalid');
  addReason(reasons, !isDigest(resourcePlan?.equipmentPlanHash), 'equipment_plan_hash_invalid');
  addReason(reasons, !isDigest(resourcePlan?.vendorCostPlanHash), 'vendor_cost_plan_hash_invalid');
  addReason(reasons, !isDigest(resourcePlan?.cashflowScheduleHash), 'cashflow_schedule_hash_invalid');
  addReason(reasons, resourcePlan?.startupFundingConfirmed !== true, 'startup_funding_unconfirmed');
  addReason(reasons, !isDigest(resourcePlan?.startupFundingEvidenceHash), 'startup_funding_evidence_invalid');
  addReason(reasons, resourcePlan?.metadataOnly !== true, 'resource_plan_metadata_boundary_invalid');
  addReason(reasons, resourcePlan?.protectedContentExcluded !== true, 'resource_plan_protected_boundary_invalid');
}

function evaluateDependencies(dependencies, reasons) {
  addReason(reasons, !hasText(dependencies?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, !hasText(dependencies?.clinicalTrialAgreementRef), 'clinical_trial_agreement_ref_absent');
  addReason(reasons, !hasText(dependencies?.riskAssessmentRef), 'risk_assessment_ref_absent');
  addReason(reasons, !hasText(dependencies?.vendorReadinessRef), 'vendor_readiness_ref_absent');
  addReason(
    reasons,
    !Array.isArray(dependencies?.evidenceHashes) ||
      dependencies.evidenceHashes.length === 0 ||
      dependencies.evidenceHashes.some((hash) => !isDigest(hash)),
    'dependency_evidence_hash_invalid',
  );
  addReason(reasons, dependencies?.metadataOnly !== true, 'budget_dependency_metadata_boundary_invalid');
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
  addReason(reasons, !hasText(review?.financeReviewerDid), 'finance_reviewer_absent');
  addReason(reasons, !hasText(review?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function buildBudgetFeasibility(input, costSummary, marginBasisPoints, reasons) {
  const conditionRefs = costSummary.conditionRefs;
  const permitted = reasons.length === 0;
  const feasibleWithConditions = permitted && (conditionRefs.length > 0 || input?.studyBudget?.status === 'approved_with_conditions');
  const material = {
    schema: BUDGET_SCHEMA,
    tenantId: input?.tenantId ?? '',
    budgetRef: input?.studyBudget?.budgetRef ?? '',
    protocolRef: input?.studyBudget?.protocolRef ?? '',
    siteRef: input?.studyBudget?.siteRef ?? '',
    sponsorRef: input?.studyBudget?.sponsorRef ?? '',
    croRef: input?.studyBudget?.croRef ?? '',
    policyRef: input?.budgetPolicy?.policyRef ?? '',
    evaluatedAtHlc: input?.budgetPolicy?.evaluatedAtHlc ?? null,
    approvedAtHlc: input?.studyBudget?.approvedAtHlc ?? null,
    currencyCode: input?.studyBudget?.currencyCode ?? '',
    marginBasisPoints: marginBasisPoints ?? null,
    contingencyBasisPoints: input?.studyBudget?.contingencyBasisPoints ?? null,
    costCoverageBasisPoints: costSummary.costCoverageBasisPoints,
    coveredCostDomains: costSummary.coveredCostDomains,
    conditionRefs,
    dependencyRefs: {
      clinicalTrialAgreementRef: input?.dependencies?.clinicalTrialAgreementRef ?? '',
      protocolFeasibilityRef: input?.dependencies?.protocolFeasibilityRef ?? '',
      riskAssessmentRef: input?.dependencies?.riskAssessmentRef ?? '',
      vendorReadinessRef: input?.dependencies?.vendorReadinessRef ?? '',
    },
  };

  return {
    ...material,
    feasibilityId: `budget_feasible_${sha256Hex(material).slice(0, 32)}`,
    feasibilityStatus: permitted
      ? feasibleWithConditions
        ? 'financially_feasible_with_conditions'
        : 'financially_feasible'
      : 'not_financially_feasible',
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true || input?.actor?.kind === 'ai_agent',
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createBudgetReceipt(input, budgetFeasibility) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did,
    artifactHash: sha256Hex(budgetFeasibility),
    artifactType: 'study_budget_feasibility',
    artifactVersion: '1',
    classification: 'sponsor-cro-confidential-metadata',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.budgetPolicy?.evaluatedAtHlc,
    sensitivityTags: ['finance_metadata', 'metadata_only', 'sponsor_cro_confidential'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input?.tenantId,
  });
}

export function evaluateStudyBudgetFeasibility(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluateBudgetPolicy(input?.budgetPolicy, reasons);
  const marginBasisPoints = evaluateStudyBudget(input?.studyBudget, input?.budgetPolicy, reasons);
  const costSummary = evaluateCostDomains(input?.costDomainReviews, policy.requiredCostDomains, input?.studyBudget, input?.budgetPolicy, reasons);
  evaluateResourcePlan(input?.resourcePlan, reasons);
  evaluateDependencies(input?.dependencies, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const budgetFeasibility = buildBudgetFeasibility(input, costSummary, marginBasisPoints, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    budgetFeasibility,
    receipt: permitted ? createBudgetReceipt(input, budgetFeasibility) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
