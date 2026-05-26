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
const VENDOR_SCHEMA = 'cybermedica.vendor_subcontractor_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.vendor_subcontractor_readiness_decision.v1';

const REQUIRED_VENDOR_CATEGORIES = Object.freeze([
  'central_lab',
  'data_management_vendor',
  'imaging_provider',
  'logistics_provider',
  'pharmacy',
  'technology_vendor',
]);

const REQUIRED_REVIEW_DOMAINS = Object.freeze([
  'contractual_obligations',
  'decommissioning',
  'issue_escalation',
  'privacy_security',
  'qualification',
  'risk_management',
  'service_level_monitoring',
  'sponsor_cro_visibility',
]);

const VENDOR_CATEGORIES = new Set(REQUIRED_VENDOR_CATEGORIES);
const POLICY_STATUSES = new Set(['active']);
const PROGRAM_STATUSES = new Set(['active']);
const QUALIFICATION_STATUSES = new Set(['qualified']);
const CRITICALITIES = new Set(['critical', 'major', 'supporting']);
const REQUIRED_PERMISSION = 'manage_vendor_readiness';

const RAW_VENDOR_FIELDS = new Set([
  'contactdetails',
  'contactemail',
  'contactname',
  'contactphone',
  'contractbody',
  'directidentifier',
  'freeformrisktext',
  'rawagreement',
  'rawcontract',
  'rawcontractbody',
  'rawcontact',
  'rawduediligence',
  'rawissue',
  'rawpayload',
  'rawqualification',
  'rawservicelevel',
  'rawvendor',
  'rawvendorcontent',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'vendorcontractbody',
  'vendornarrative',
]);

const SECRET_VENDOR_FIELDS = new Set([
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

function assertNoRawVendorContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawVendorContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_VENDOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw vendor or subcontractor content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_VENDOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`vendor or subcontractor secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawVendorContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawVendorContent(input ?? {});
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

function vendorIdentity(vendor) {
  return hasText(vendor?.vendorRef) ? vendor.vendorRef : 'unclassified_vendor';
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
    'vendor_readiness_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateVendorPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'vendor_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'vendor_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'vendor_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'vendor_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'vendor_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'vendor_policy_evaluation_time_invalid');

  const requiredVendorCategories = sortedTextList(policy?.requiredVendorCategories);
  const requiredReviewDomains = sortedTextList(policy?.requiredReviewDomains);
  evaluateRequiredSet(
    requiredVendorCategories,
    REQUIRED_VENDOR_CATEGORIES,
    'vendor_policy_category_missing',
    'vendor_policy_category_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredReviewDomains,
    REQUIRED_REVIEW_DOMAINS,
    'vendor_policy_review_domain_missing',
    'vendor_policy_review_domain_unsupported',
    reasons,
  );

  return {
    requiredVendorCategories: requiredVendorCategories.length > 0 ? requiredVendorCategories : [...REQUIRED_VENDOR_CATEGORIES],
    requiredReviewDomains: requiredReviewDomains.length > 0 ? requiredReviewDomains : [...REQUIRED_REVIEW_DOMAINS],
  };
}

function evaluateVendorProgram(program, reasons) {
  addReason(reasons, !hasText(program?.programRef), 'vendor_program_ref_absent');
  addReason(reasons, !hasText(program?.protocolRef), 'vendor_program_protocol_ref_absent');
  addReason(reasons, !hasText(program?.siteRef), 'vendor_program_site_ref_absent');
  addReason(reasons, !PROGRAM_STATUSES.has(program?.status), 'vendor_program_not_active');
  addReason(reasons, !isDigest(program?.qualificationProcedureHash), 'vendor_qualification_procedure_hash_invalid');
  addReason(reasons, !isDigest(program?.subcontractorOversightProcedureHash), 'subcontractor_oversight_procedure_hash_invalid');
  addReason(reasons, !isDigest(program?.sponsorCroVisibilityPolicyHash), 'sponsor_cro_visibility_policy_hash_invalid');
  addReason(reasons, !isDigest(program?.issueManagementProcedureHash), 'vendor_issue_management_procedure_hash_invalid');
  addReason(reasons, program?.metadataOnly !== true, 'vendor_program_metadata_boundary_invalid');
  addReason(reasons, program?.protectedContentExcluded !== true, 'vendor_program_protected_boundary_invalid');
  addReason(reasons, hlcTuple(program?.openedAtHlc) === null, 'vendor_program_open_time_invalid');
  addReason(reasons, hlcTuple(program?.compiledAtHlc) === null, 'vendor_program_compile_time_invalid');
  addReason(reasons, hlcTuple(program?.reviewedAtHlc) === null, 'vendor_program_review_time_invalid');
  addReason(reasons, !hlcBefore(program?.openedAtHlc, program?.compiledAtHlc), 'vendor_program_compile_order_invalid');
  addReason(reasons, !hlcBefore(program?.compiledAtHlc, program?.reviewedAtHlc), 'vendor_program_review_order_invalid');
}

function evaluateProtectedDataBoundary(vendor, vendorRef, reasons) {
  if (vendor?.handlesProtectedData !== true) {
    return false;
  }
  addReason(reasons, !isDigest(vendor?.dataProcessingAgreementHash), `protected_data_vendor_dpa_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.privacyBoundaryHash), `protected_data_vendor_privacy_boundary_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.accessPolicyHash), `protected_data_vendor_access_policy_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.dataMinimizationHash), `protected_data_vendor_minimization_absent:${vendorRef}`);
  return true;
}

function evaluateCriticalVendor(vendor, vendorRef, reasons) {
  if (vendor?.criticality !== 'critical') {
    return false;
  }
  addReason(reasons, !hasText(vendor?.riskAssessmentRef), `critical_vendor_risk_ref_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.contingencyPlanHash), `critical_vendor_contingency_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.businessContinuityHash), `critical_vendor_continuity_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.issueEscalationPathHash), `critical_vendor_escalation_absent:${vendorRef}`);
  return true;
}

function evaluateVendor(vendor, evaluatedAtHlc, reasons) {
  const vendorRef = vendorIdentity(vendor);

  addReason(reasons, !hasText(vendor?.vendorRef), 'vendor_ref_absent');
  addReason(reasons, !VENDOR_CATEGORIES.has(vendor?.vendorCategory), `vendor_category_invalid:${vendorRef}`);
  addReason(reasons, !hasText(vendor?.vendorRole), `vendor_role_absent:${vendorRef}`);
  addReason(reasons, !QUALIFICATION_STATUSES.has(vendor?.qualificationStatus), `vendor_not_qualified:${vendorRef}`);
  addReason(reasons, !CRITICALITIES.has(vendor?.criticality), `vendor_criticality_invalid:${vendorRef}`);
  addReason(reasons, sortedTextList(vendor?.delegatedDutyRefs).length === 0, `vendor_delegated_duty_absent:${vendorRef}`);
  addReason(reasons, sortedTextList(vendor?.linkedProtocolRefs).length === 0, `vendor_protocol_link_absent:${vendorRef}`);
  addReason(reasons, !hasText(vendor?.ownerDid), `vendor_owner_absent:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.qualificationEvidenceHash), `vendor_qualification_evidence_invalid:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.dueDiligenceHash), `vendor_due_diligence_invalid:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.contractAgreementHash), `vendor_contract_agreement_invalid:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.serviceLevelHash), `vendor_service_level_invalid:${vendorRef}`);
  addReason(reasons, !isDigest(vendor?.oversightReviewHash), `vendor_oversight_review_invalid:${vendorRef}`);
  addReason(reasons, !hlcAfter(vendor?.renewalDueHlc, evaluatedAtHlc), `vendor_renewal_due_or_invalid:${vendorRef}`);
  addReason(reasons, hlcTuple(vendor?.lastReviewedAtHlc) === null, `vendor_last_review_time_invalid:${vendorRef}`);
  addReason(reasons, !hlcBefore(vendor?.lastReviewedAtHlc, evaluatedAtHlc), `vendor_last_review_order_invalid:${vendorRef}`);
  addReason(reasons, vendor?.metadataOnly !== true, `vendor_metadata_boundary_invalid:${vendorRef}`);
  addReason(reasons, vendor?.protectedContentExcluded !== true, `vendor_protected_boundary_invalid:${vendorRef}`);

  const protectedDataVendor = evaluateProtectedDataBoundary(vendor, vendorRef, reasons);
  const criticalVendor = evaluateCriticalVendor(vendor, vendorRef, reasons);

  return {
    vendorRef,
    vendorCategory: vendor?.vendorCategory,
    criticalVendor,
    protectedDataVendor,
  };
}

function evaluateVendors(vendors, requiredCategories, evaluatedAtHlc, reasons) {
  const rows = Array.isArray(vendors) ? vendors : [];
  addReason(reasons, rows.length === 0, 'vendor_collection_absent');

  const summaries = rows.map((vendor) => evaluateVendor(vendor, evaluatedAtHlc, reasons));
  const categoriesCovered = uniqueSorted(summaries.map((summary) => summary.vendorCategory).filter((category) => VENDOR_CATEGORIES.has(category)));

  for (const category of requiredCategories) {
    addReason(reasons, !categoriesCovered.includes(category), `required_vendor_category_missing:${category}`);
  }

  return {
    categoriesCovered,
    vendorRefs: uniqueSorted(summaries.map((summary) => summary.vendorRef)),
    criticalVendorRefs: uniqueSorted(summaries.filter((summary) => summary.criticalVendor).map((summary) => summary.vendorRef)),
    protectedDataVendorRefs: uniqueSorted(summaries.filter((summary) => summary.protectedDataVendor).map((summary) => summary.vendorRef)),
  };
}

function evaluateOversight(oversight, requiredReviewDomains, program, reasons) {
  addReason(reasons, !hasText(oversight?.reviewRef), 'vendor_oversight_review_ref_absent');
  addReason(reasons, !isDigest(oversight?.sponsorCroDisclosureLogHash), 'sponsor_cro_disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(oversight?.escalationRegisterHash), 'vendor_escalation_register_hash_invalid');
  addReason(reasons, !isDigest(oversight?.decommissioningPlanHash), 'vendor_decommissioning_plan_hash_invalid');
  addReason(reasons, oversight?.humanReviewed !== true, 'vendor_oversight_human_review_absent');
  addReason(reasons, !hasText(oversight?.reviewedByDid), 'vendor_oversight_reviewer_absent');
  addReason(reasons, hlcTuple(oversight?.reviewedAtHlc) === null, 'vendor_oversight_review_time_invalid');
  addReason(reasons, !hlcAfter(oversight?.reviewedAtHlc, program?.reviewedAtHlc), 'vendor_oversight_review_order_invalid');
  addReason(reasons, oversight?.metadataOnly !== true, 'vendor_oversight_metadata_boundary_invalid');

  const reviewDomains = sortedTextList(oversight?.reviewDomains);
  for (const domain of requiredReviewDomains) {
    addReason(reasons, !reviewDomains.includes(domain), `vendor_review_domain_missing:${domain}`);
  }
  for (const domain of reviewDomains) {
    addReason(reasons, !REQUIRED_REVIEW_DOMAINS.includes(domain), `vendor_review_domain_unsupported:${domain}`);
  }

  const openCriticalIssues = sortedTextList(oversight?.openCriticalIssueRefs);
  for (const issueRef of openCriticalIssues) {
    reasons.push(`open_critical_vendor_issue:${issueRef}`);
  }

  return {
    reviewDomains,
    openCriticalIssueRefs: openCriticalIssues,
  };
}

function evaluateDependencyEvidence(evidence, reasons) {
  addReason(reasons, !hasText(evidence?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, sortedTextList(evidence?.riskAssessmentRefs).length === 0, 'risk_assessment_ref_absent');
  addReason(reasons, sortedTextList(evidence?.governedIntegrationRefs).length === 0, 'governed_integration_ref_absent');
  addReason(reasons, sortedTextList(evidence?.diligencePacketRefs).length === 0, 'diligence_packet_ref_absent');
  addReason(
    reasons,
    !Array.isArray(evidence?.evidenceHashes) ||
      evidence.evidenceHashes.length === 0 ||
      evidence.evidenceHashes.some((hash) => !isDigest(hash)),
    'vendor_dependency_evidence_hash_invalid',
  );
  addReason(reasons, evidence?.metadataOnly !== true, 'vendor_dependency_metadata_boundary_invalid');
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

function buildReadiness(input, vendorSummary, oversightSummary, reasons) {
  const material = {
    schema: VENDOR_SCHEMA,
    tenantId: input?.tenantId ?? '',
    programRef: input?.vendorProgram?.programRef ?? '',
    protocolRef: input?.vendorProgram?.protocolRef ?? '',
    siteRef: input?.vendorProgram?.siteRef ?? '',
    policyRef: input?.vendorPolicy?.policyRef ?? '',
    evaluatedAtHlc: input?.vendorPolicy?.evaluatedAtHlc ?? null,
    vendorCategoriesCovered: vendorSummary.categoriesCovered,
    vendorRefs: vendorSummary.vendorRefs,
    criticalVendorRefs: vendorSummary.criticalVendorRefs,
    protectedDataVendorRefs: vendorSummary.protectedDataVendorRefs,
    reviewRef: input?.oversight?.reviewRef ?? '',
    reviewDomainsCovered: oversightSummary.reviewDomains,
    dependencyRefs: {
      diligencePacketRefs: sortedTextList(input?.dependencyEvidence?.diligencePacketRefs),
      governedIntegrationRefs: sortedTextList(input?.dependencyEvidence?.governedIntegrationRefs),
      protocolFeasibilityRef: input?.dependencyEvidence?.protocolFeasibilityRef ?? '',
      riskAssessmentRefs: sortedTextList(input?.dependencyEvidence?.riskAssessmentRefs),
    },
  };

  return {
    ...material,
    readinessId: `vendor_ready_${sha256Hex(material).slice(0, 32)}`,
    readinessStatus: reasons.length === 0 ? 'ready_for_protocol_use' : 'not_ready',
    vendorCategoriesCovered: vendorSummary.categoriesCovered,
    reviewDomainsCovered: oversightSummary.reviewDomains,
    openCriticalIssueRefs: oversightSummary.openCriticalIssueRefs,
    vendorCount: vendorSummary.vendorRefs.length,
    criticalVendorCount: vendorSummary.criticalVendorRefs.length,
    protectedDataVendorCount: vendorSummary.protectedDataVendorRefs.length,
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createVendorReceipt(input, readiness) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did,
    artifactHash: sha256Hex(readiness),
    artifactType: 'vendor_subcontractor_readiness',
    artifactVersion: '1',
    classification: 'quality-evidence',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.vendorPolicy?.evaluatedAtHlc,
    sensitivityTags: ['metadata_only', 'sponsor_cro_confidential', 'vendor_subcontractor'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input?.tenantId,
  });
}

export function evaluateVendorSubcontractorReadiness(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluateVendorPolicy(input?.vendorPolicy, reasons);
  evaluateVendorProgram(input?.vendorProgram, reasons);
  const vendorSummary = evaluateVendors(input?.vendors, policy.requiredVendorCategories, input?.vendorPolicy?.evaluatedAtHlc, reasons);
  const oversightSummary = evaluateOversight(input?.oversight, policy.requiredReviewDomains, input?.vendorProgram, reasons);
  evaluateDependencyEvidence(input?.dependencyEvidence, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const readiness = buildReadiness(input, vendorSummary, oversightSummary, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    vendorReadiness: readiness,
    receipt: permitted ? createVendorReceipt(input, readiness) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
