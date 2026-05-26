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
const READINESS_SCHEMA = 'cybermedica.insurance_claims_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.insurance_claims_readiness_decision.v1';

const REQUIRED_COVERAGE_DOMAINS = Object.freeze([
  'clinical_trial_liability',
  'general_liability',
  'malpractice_negligence',
  'participant_injury_compensation',
  'privacy_security_claims',
  'product_handling_liability',
  'professional_liability',
  'sponsor_indemnity',
]);

const REQUIRED_REVIEW_DOMAINS = Object.freeze([
  'claims_reporting',
  'coverage_limits',
  'deductible_exposure',
  'exclusions_review',
  'indemnification_alignment',
  'legal_review',
  'non_waiver_non_negligence',
  'participant_compensation',
]);

const COVERAGE_DOMAINS = new Set(REQUIRED_COVERAGE_DOMAINS);
const REVIEW_DOMAINS = new Set(REQUIRED_REVIEW_DOMAINS);
const POLICY_STATUSES = new Set(['active']);
const PACKAGE_STATUSES = new Set(['approved', 'approved_with_conditions']);
const COVERAGE_STATUSES = new Set(['covered', 'covered_with_conditions', 'deferred', 'not_covered']);
const REQUIRED_PERMISSION = 'assess_insurance_claims_readiness';

const RAW_INSURANCE_FIELDS = new Set([
  'carrierpolicybody',
  'claimdetails',
  'claimnarrative',
  'directidentifier',
  'freetextclaimnotes',
  'insurancecertificatebody',
  'insurancepolicybody',
  'medicalrecord',
  'negligenceanalysis',
  'participantname',
  'patientname',
  'policybody',
  'rawclaim',
  'rawclaimbody',
  'rawcoverage',
  'rawinsurance',
  'rawlegalanalysis',
  'rawpayload',
  'rawpolicy',
  'sourcedocumentbody',
  'waivertext',
]);

const SECRET_INSURANCE_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'carrierportaltoken',
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

function assertNoRawInsuranceContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInsuranceContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INSURANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw insurance claims content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INSURANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`insurance claims secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawInsuranceContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInsuranceContent(input ?? {});
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

function calculateCoverageBasisPoints(coverageMinorUnits, exposureMinorUnits) {
  if (!isSafePositiveInteger(coverageMinorUnits) || !isSafePositiveInteger(exposureMinorUnits)) {
    return null;
  }
  const calculated = Number((BigInt(coverageMinorUnits) * 10_000n) / BigInt(exposureMinorUnits));
  return Math.min(calculated, 10_000);
}

function coverageIdentity(row) {
  return hasText(row?.domain) ? row.domain : 'unknown_coverage_domain';
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
    'insurance_claims_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateInsurancePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'insurance_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'insurance_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'insurance_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'insurance_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'insurance_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'insurance_policy_evaluation_time_invalid');
  addReason(reasons, !isBasisPoints(policy?.minimumCoverageBasisPoints), 'minimum_coverage_basis_points_invalid');
  addReason(reasons, !isBasisPoints(policy?.maximumDeductibleBasisPoints), 'maximum_deductible_basis_points_invalid');

  const requiredCoverageDomains = sortedTextList(policy?.requiredCoverageDomains);
  const requiredReviewDomains = sortedTextList(policy?.requiredReviewDomains);
  evaluateRequiredSet(
    requiredCoverageDomains,
    REQUIRED_COVERAGE_DOMAINS,
    COVERAGE_DOMAINS,
    'insurance_policy_coverage_domain_missing',
    'insurance_policy_coverage_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredReviewDomains,
    REQUIRED_REVIEW_DOMAINS,
    REVIEW_DOMAINS,
    'insurance_policy_review_domain_missing',
    'insurance_policy_review_domain_unsupported',
    reasons,
  );

  return {
    requiredCoverageDomains: requiredCoverageDomains.length > 0 ? requiredCoverageDomains : [...REQUIRED_COVERAGE_DOMAINS],
    requiredReviewDomains: requiredReviewDomains.length > 0 ? requiredReviewDomains : [...REQUIRED_REVIEW_DOMAINS],
  };
}

function evaluateInsurancePackage(pkg, policy, reasons) {
  addReason(reasons, !hasText(pkg?.packageRef), 'insurance_package_ref_absent');
  addReason(reasons, !hasText(pkg?.protocolRef), 'insurance_package_protocol_ref_absent');
  addReason(reasons, !hasText(pkg?.siteRef), 'insurance_package_site_ref_absent');
  addReason(reasons, !hasText(pkg?.sponsorRef), 'insurance_package_sponsor_ref_absent');
  addReason(reasons, !hasText(pkg?.croRef), 'insurance_package_cro_ref_absent');
  addReason(reasons, !PACKAGE_STATUSES.has(pkg?.status), 'insurance_package_status_not_approved');
  addReason(reasons, !hasText(pkg?.currencyCode) || !CURRENCY_CODE.test(pkg.currencyCode), 'currency_code_invalid');
  addReason(reasons, !isSafePositiveInteger(pkg?.aggregateCoverageMinorUnits), 'aggregate_coverage_minor_units_invalid');
  addReason(reasons, !isSafePositiveInteger(pkg?.aggregateExposureMinorUnits), 'aggregate_exposure_minor_units_invalid');
  addReason(reasons, !isDigest(pkg?.certificateBundleHash), 'insurance_certificate_bundle_hash_invalid');
  addReason(reasons, !isDigest(pkg?.claimsHandlingProcedureHash), 'claims_handling_procedure_hash_invalid');
  addReason(reasons, !isDigest(pkg?.malpracticeReviewHash), 'malpractice_review_hash_invalid');
  addReason(reasons, !isDigest(pkg?.nonWaiverNegligenceReviewHash), 'non_waiver_negligence_review_hash_invalid');
  addReason(reasons, pkg?.metadataOnly !== true, 'insurance_package_metadata_boundary_invalid');
  addReason(reasons, pkg?.protectedContentExcluded !== true, 'insurance_package_protected_boundary_invalid');
  addReason(reasons, hlcTuple(pkg?.createdAtHlc) === null, 'insurance_package_created_time_invalid');
  addReason(reasons, hlcTuple(pkg?.approvedAtHlc) === null, 'insurance_package_approved_time_invalid');
  addReason(reasons, !hlcBefore(pkg?.createdAtHlc, pkg?.approvedAtHlc), 'insurance_package_approval_order_invalid');
  addReason(reasons, !hlcAfter(pkg?.approvedAtHlc, policy?.evaluatedAtHlc), 'insurance_package_approved_before_policy_evaluation');

  const aggregateCoverageBasisPoints = calculateCoverageBasisPoints(pkg?.aggregateCoverageMinorUnits, pkg?.aggregateExposureMinorUnits);
  addReason(
    reasons,
    aggregateCoverageBasisPoints !== null &&
      isBasisPoints(policy?.minimumCoverageBasisPoints) &&
      aggregateCoverageBasisPoints < policy.minimumCoverageBasisPoints,
    'aggregate_coverage_below_minimum',
  );

  return aggregateCoverageBasisPoints;
}

function evaluateCoverageDomain(row, policy, reasons) {
  const domain = coverageIdentity(row);
  const ready = row?.status === 'covered' || row?.status === 'covered_with_conditions';
  const coverageBasisPoints = calculateCoverageBasisPoints(row?.coverageMinorUnits, row?.estimatedExposureMinorUnits);
  const deductibleBasisPoints = calculateCoverageBasisPoints(row?.deductibleMinorUnits, row?.estimatedExposureMinorUnits);

  addReason(reasons, !COVERAGE_DOMAINS.has(row?.domain), `coverage_domain_invalid:${domain}`);
  addReason(reasons, !COVERAGE_STATUSES.has(row?.status), `coverage_domain_status_invalid:${domain}`);
  addReason(reasons, COVERAGE_STATUSES.has(row?.status) && !ready, `coverage_domain_not_ready:${domain}`);
  addReason(reasons, !isDigest(row?.carrierEvidenceHash), `carrier_evidence_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.policyCertificateHash), `policy_certificate_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.coverageLimitHash), `coverage_limit_hash_invalid:${domain}`);
  addReason(reasons, !isDigest(row?.exclusionReviewHash), `exclusion_review_hash_invalid:${domain}`);
  addReason(reasons, !hasText(row?.ownerDid), `coverage_domain_owner_absent:${domain}`);
  addReason(reasons, !isSafePositiveInteger(row?.coverageMinorUnits), `coverage_minor_units_invalid:${domain}`);
  addReason(reasons, !isSafePositiveInteger(row?.estimatedExposureMinorUnits), `estimated_exposure_minor_units_invalid:${domain}`);
  addReason(reasons, !Number.isSafeInteger(row?.deductibleMinorUnits) || row.deductibleMinorUnits < 0, `deductible_minor_units_invalid:${domain}`);
  addReason(
    reasons,
    coverageBasisPoints !== null &&
      isBasisPoints(policy?.minimumCoverageBasisPoints) &&
      coverageBasisPoints < policy.minimumCoverageBasisPoints,
    `coverage_amount_below_exposure:${domain}`,
  );
  addReason(
    reasons,
    deductibleBasisPoints !== null &&
      isBasisPoints(policy?.maximumDeductibleBasisPoints) &&
      deductibleBasisPoints > policy.maximumDeductibleBasisPoints,
    `deductible_over_limit:${domain}`,
  );
  addReason(reasons, row?.metadataOnly !== true, `coverage_domain_metadata_boundary_invalid:${domain}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `coverage_domain_protected_boundary_invalid:${domain}`);

  const openExclusionRefs = sortedTextList(row?.openExclusionRefs);
  for (const exclusionRef of openExclusionRefs) {
    reasons.push(`open_exclusion_unmitigated:${exclusionRef}`);
  }

  if (row?.status === 'covered_with_conditions') {
    addReason(reasons, !hasText(row?.conditionRef), `conditional_coverage_condition_ref_absent:${domain}`);
    addReason(reasons, !isDigest(row?.mitigationHash), `conditional_coverage_mitigation_invalid:${domain}`);
  }

  return {
    domain,
    ready,
    conditionRef: row?.conditionRef,
    coverageBasisPoints,
    deductibleBasisPoints,
  };
}

function evaluateCoverageDomains(rows, requiredCoverageDomains, policy, reasons) {
  const coverageRows = Array.isArray(rows) ? rows : [];
  addReason(reasons, coverageRows.length === 0, 'coverage_domain_collection_absent');

  const summaries = coverageRows.map((row) => evaluateCoverageDomain(row, policy, reasons));
  const coveredCoverageDomains = uniqueSorted(
    summaries.filter((summary) => summary.ready && COVERAGE_DOMAINS.has(summary.domain)).map((summary) => summary.domain),
  );

  for (const domain of requiredCoverageDomains) {
    addReason(reasons, !coveredCoverageDomains.includes(domain), `required_coverage_domain_missing:${domain}`);
  }

  return {
    conditionRefs: uniqueSorted(summaries.map((summary) => summary.conditionRef)),
    coveredCoverageDomains,
    coverageDomainBasisPoints: Number((BigInt(coveredCoverageDomains.length) * 10_000n) / BigInt(REQUIRED_COVERAGE_DOMAINS.length)),
  };
}

function evaluateLegalReview(review, requiredReviewDomains, pkg, reasons) {
  addReason(reasons, !hasText(review?.reviewRef), 'legal_review_ref_absent');
  addReason(reasons, !hasText(review?.legalReviewerDid), 'legal_reviewer_absent');
  addReason(reasons, !hasText(review?.financeReviewerDid), 'finance_reviewer_absent');
  addReason(reasons, !hasText(review?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, !isDigest(review?.participantCompensationPathHash), 'participant_compensation_path_invalid');
  addReason(reasons, !isDigest(review?.claimsEscalationPathHash), 'claims_escalation_path_invalid');
  addReason(reasons, !isDigest(review?.indemnificationMatrixHash), 'indemnification_matrix_invalid');
  addReason(reasons, !isDigest(review?.consentNonWaiverLinkHash), 'consent_non_waiver_link_invalid');
  addReason(reasons, review?.humanReviewed !== true, 'legal_review_human_review_absent');
  addReason(reasons, review?.metadataOnly !== true, 'legal_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'legal_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'legal_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, pkg?.approvedAtHlc), 'legal_review_order_invalid');

  const reviewDomains = sortedTextList(review?.reviewDomains);
  for (const domain of requiredReviewDomains) {
    addReason(reasons, !reviewDomains.includes(domain), `legal_review_domain_missing:${domain}`);
  }
  for (const domain of reviewDomains) {
    addReason(reasons, !REVIEW_DOMAINS.has(domain), `legal_review_domain_unsupported:${domain}`);
  }

  return reviewDomains;
}

function evaluateDependencies(dependencies, reasons) {
  addReason(reasons, !hasText(dependencies?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, !hasText(dependencies?.clinicalTrialAgreementRef), 'clinical_trial_agreement_ref_absent');
  addReason(reasons, !hasText(dependencies?.riskAssessmentRef), 'risk_assessment_ref_absent');
  addReason(reasons, !hasText(dependencies?.consentMaterialsRef), 'consent_materials_ref_absent');
  addReason(
    reasons,
    !Array.isArray(dependencies?.evidenceHashes) ||
      dependencies.evidenceHashes.length === 0 ||
      dependencies.evidenceHashes.some((hash) => !isDigest(hash)),
    'dependency_evidence_hash_invalid',
  );
  addReason(reasons, dependencies?.metadataOnly !== true, 'insurance_dependency_metadata_boundary_invalid');
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

function buildReadiness(input, coverageSummary, reviewDomainsCovered, aggregateCoverageBasisPoints, reasons) {
  const permitted = reasons.length === 0;
  const conditionRefs = coverageSummary.conditionRefs;
  const readyWithConditions = permitted && (conditionRefs.length > 0 || input?.insurancePackage?.status === 'approved_with_conditions');
  const material = {
    schema: READINESS_SCHEMA,
    tenantId: input?.tenantId ?? '',
    packageRef: input?.insurancePackage?.packageRef ?? '',
    protocolRef: input?.insurancePackage?.protocolRef ?? '',
    siteRef: input?.insurancePackage?.siteRef ?? '',
    sponsorRef: input?.insurancePackage?.sponsorRef ?? '',
    croRef: input?.insurancePackage?.croRef ?? '',
    policyRef: input?.insurancePolicy?.policyRef ?? '',
    evaluatedAtHlc: input?.insurancePolicy?.evaluatedAtHlc ?? null,
    approvedAtHlc: input?.insurancePackage?.approvedAtHlc ?? null,
    currencyCode: input?.insurancePackage?.currencyCode ?? '',
    aggregateCoverageBasisPoints,
    coverageDomainBasisPoints: coverageSummary.coverageDomainBasisPoints,
    coveredCoverageDomains: coverageSummary.coveredCoverageDomains,
    reviewDomainsCovered,
    conditionRefs,
    dependencyRefs: {
      clinicalTrialAgreementRef: input?.dependencies?.clinicalTrialAgreementRef ?? '',
      consentMaterialsRef: input?.dependencies?.consentMaterialsRef ?? '',
      protocolFeasibilityRef: input?.dependencies?.protocolFeasibilityRef ?? '',
      riskAssessmentRef: input?.dependencies?.riskAssessmentRef ?? '',
    },
  };

  return {
    ...material,
    readinessId: `insurance_claims_ready_${sha256Hex(material).slice(0, 32)}`,
    readinessStatus: permitted
      ? readyWithConditions
        ? 'insurance_claims_ready_with_conditions'
        : 'insurance_claims_ready'
      : 'insurance_claims_not_ready',
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true || input?.actor?.kind === 'ai_agent',
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createReadinessReceipt(input, readiness) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did,
    artifactHash: sha256Hex(readiness),
    artifactType: 'insurance_claims_readiness',
    artifactVersion: '1',
    classification: 'sponsor-cro-confidential-metadata',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.insurancePolicy?.evaluatedAtHlc,
    sensitivityTags: ['insurance_claims', 'legal_review', 'metadata_only', 'sponsor_cro_confidential'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input?.tenantId,
  });
}

export function evaluateInsuranceClaimsReadiness(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluateInsurancePolicy(input?.insurancePolicy, reasons);
  const aggregateCoverageBasisPoints = evaluateInsurancePackage(input?.insurancePackage, input?.insurancePolicy, reasons);
  const coverageSummary = evaluateCoverageDomains(input?.coverageDomains, policy.requiredCoverageDomains, input?.insurancePolicy, reasons);
  const reviewDomainsCovered = evaluateLegalReview(input?.legalReview, policy.requiredReviewDomains, input?.insurancePackage, reasons);
  evaluateDependencies(input?.dependencies, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const insuranceReadiness = buildReadiness(input, coverageSummary, reviewDomainsCovered, aggregateCoverageBasisPoints, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    insuranceReadiness,
    receipt: permitted ? createReadinessReceipt(input, insuranceReadiness) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
