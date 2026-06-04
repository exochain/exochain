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
const REQUIRED_PERMISSION = 'risk_framework_manage';
const FRAMEWORK_SCHEMA = 'cybermedica.risk_management_framework.v1';
const DECISION_SCHEMA = 'cybermedica.risk_management_framework_decision.v1';

const REQUIRED_FRAMEWORK_DOMAINS = Object.freeze([
  'assessment_method',
  'criteria',
  'escalation',
  'mitigation_tracking',
  'risk_identification',
  'safety_planning',
  'staff_training',
  'treatment_controls',
]);

const REQUIRED_REGISTER_CATEGORIES = Object.freeze([
  'consent',
  'data_integrity',
  'facility',
  'operational',
  'participant_safety',
  'product_handling',
  'regulatory',
  'staffing',
  'vendor',
]);

const REQUIRED_TRAINING_DOMAINS = Object.freeze([
  'assessment_method',
  'escalation',
  'mitigation_tracking',
  'safety_planning',
]);

const REQUIRED_ESCALATION_TRIGGERS = Object.freeze([
  'critical_residual_risk',
  'participant_safety_risk',
  'unmitigated_high_risk',
]);

const FRAMEWORK_DOMAINS = new Set(REQUIRED_FRAMEWORK_DOMAINS);
const REGISTER_CATEGORIES = new Set(REQUIRED_REGISTER_CATEGORIES);
const TRAINING_DOMAINS = new Set(REQUIRED_TRAINING_DOMAINS);
const ESCALATION_TRIGGERS = new Set(REQUIRED_ESCALATION_TRIGGERS);
const FRAMEWORK_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['implemented', 'implemented_with_conditions']);
const REGISTER_STATUSES = new Set(['current']);
const ENTRY_STATUSES = new Set(['controlled', 'monitoring']);

const RAW_RISK_FRAMEWORK_FIELDS = new Set([
  'directidentifier',
  'freetextrisk',
  'freetextriskframework',
  'medicalrecord',
  'participantname',
  'patientname',
  'rawcriteria',
  'rawescalation',
  'rawframework',
  'rawmitigation',
  'rawrisk',
  'rawriskframeworktext',
  'rawriskregister',
  'rawsafetyplan',
  'sourcedocumentbody',
  'sponsorconfidentialrisk',
]);

const SECRET_RISK_FRAMEWORK_FIELDS = new Set([
  'accesstoken',
  'adaptersecret',
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

function isNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRiskFrameworkProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRiskFrameworkProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RISK_FRAMEWORK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`risk management raw content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RISK_FRAMEWORK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`risk management secret field is not allowed at ${path}.${key}`);
    }
    assertNoRiskFrameworkProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRiskFrameworkProtectedContent(input ?? {});
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, supported, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !supported.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.siteId), 'site_id_absent');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_time_invalid');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateFramework(framework, checkedAtHlc, reasons) {
  addReason(reasons, !hasText(framework?.frameworkRef), 'framework_ref_absent');
  addReason(reasons, !hasText(framework?.policyRef), 'framework_policy_ref_absent');
  addReason(reasons, !hasText(framework?.version), 'framework_version_absent');
  addReason(reasons, !FRAMEWORK_STATUSES.has(framework?.status), 'framework_not_active');
  addReason(reasons, !isDigest(framework?.frameworkHash), 'framework_hash_invalid');
  addReason(reasons, framework?.metadataOnly !== true, 'framework_metadata_boundary_invalid');
  addReason(reasons, framework?.protectedContentExcluded !== true, 'framework_protected_boundary_invalid');
  addReason(reasons, framework?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(framework?.approvedAtHlc) === null, 'framework_approval_time_invalid');
  addReason(reasons, hlcTuple(framework?.reviewDueHlc) === null, 'framework_review_due_time_invalid');
  addReason(reasons, !hlcAfter(framework?.reviewDueHlc, checkedAtHlc), 'framework_review_overdue');

  const rows = Array.isArray(framework?.domainEvidence) ? framework.domainEvidence : [];
  addReason(reasons, rows.length === 0, 'framework_domain_evidence_absent');

  const implementedDomains = uniqueSorted(
    rows
      .filter((row) => DOMAIN_STATUSES.has(row?.status) && FRAMEWORK_DOMAINS.has(row?.domain))
      .map((row) => row.domain),
  );
  evaluateRequiredSet(
    implementedDomains,
    REQUIRED_FRAMEWORK_DOMAINS,
    FRAMEWORK_DOMAINS,
    'framework_domain_missing',
    'framework_domain_unsupported',
    reasons,
  );

  for (const row of rows) {
    const domain = hasText(row?.domain) ? row.domain : 'unknown';
    addReason(reasons, !FRAMEWORK_DOMAINS.has(row?.domain), `framework_domain_invalid:${domain}`);
    addReason(reasons, !DOMAIN_STATUSES.has(row?.status), `framework_domain_status_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `framework_domain_evidence_hash_invalid:${domain}`);
    addReason(reasons, !hasText(row?.ownerDid), `framework_domain_owner_absent:${domain}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `framework_domain_review_time_invalid:${domain}`);
    addReason(
      reasons,
      hlcTuple(row?.reviewedAtHlc) !== null && !hlcAfter(row.reviewedAtHlc, framework?.approvedAtHlc),
      `framework_domain_review_before_approval:${domain}`,
    );
    addReason(
      reasons,
      hlcTuple(row?.reviewedAtHlc) !== null && hlcAfter(row.reviewedAtHlc, checkedAtHlc),
      `framework_domain_review_after_check:${domain}`,
    );
  }

  return implementedDomains;
}

function evaluateCriteria(criteria, reasons) {
  addReason(reasons, !hasText(criteria?.criteriaRef), 'risk_criteria_ref_absent');
  addReason(reasons, !isDigest(criteria?.criteriaHash), 'risk_criteria_hash_invalid');
  addReason(reasons, criteria?.metadataOnly !== true, 'risk_criteria_metadata_boundary_invalid');
  addReason(reasons, criteria?.probabilityScaleMin !== 1, 'probability_scale_min_invalid');
  addReason(reasons, criteria?.probabilityScaleMax !== 5, 'probability_scale_max_invalid');
  addReason(reasons, criteria?.severityScaleMin !== 1, 'severity_scale_min_invalid');
  addReason(reasons, criteria?.severityScaleMax !== 5, 'severity_scale_max_invalid');
  addReason(reasons, criteria?.detectabilityScaleMin !== 1, 'detectability_scale_min_invalid');
  addReason(reasons, criteria?.detectabilityScaleMax !== 5, 'detectability_scale_max_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(criteria?.acceptanceThresholdScore) || criteria.acceptanceThresholdScore < 1,
    'risk_acceptance_threshold_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(criteria?.escalationThresholdScore) || criteria.escalationThresholdScore < 1,
    'risk_escalation_threshold_invalid',
  );
  addReason(
    reasons,
    Number.isSafeInteger(criteria?.acceptanceThresholdScore) &&
      Number.isSafeInteger(criteria?.escalationThresholdScore) &&
      criteria.acceptanceThresholdScore >= criteria.escalationThresholdScore,
    'risk_acceptance_threshold_above_escalation_threshold',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(criteria?.reviewFrequencyDays) || criteria.reviewFrequencyDays <= 0,
    'risk_review_frequency_invalid',
  );
}

function evaluateRegisterEntry(entry, reasons) {
  const riskRef = hasText(entry?.riskRef) ? entry.riskRef : 'unknown';
  addReason(reasons, !hasText(entry?.riskRef), 'risk_register_entry_ref_absent');
  addReason(reasons, !REGISTER_CATEGORIES.has(entry?.category), `risk_register_category_invalid:${riskRef}`);
  addReason(reasons, !ENTRY_STATUSES.has(entry?.status), `risk_register_entry_status_invalid:${riskRef}`);
  addReason(reasons, !hasText(entry?.ownerDid), `risk_register_owner_absent:${riskRef}`);
  addReason(
    reasons,
    !Number.isSafeInteger(entry?.initialRiskScore) || entry.initialRiskScore < 1,
    `initial_risk_score_invalid:${riskRef}`,
  );
  addReason(
    reasons,
    !Number.isSafeInteger(entry?.residualRiskScore) || entry.residualRiskScore < 1,
    `residual_risk_score_invalid:${riskRef}`,
  );
  addReason(reasons, !isDigest(entry?.treatmentPlanHash), `treatment_plan_hash_invalid:${riskRef}`);
  addReason(reasons, !isDigest(entry?.controlEvidenceHash), `control_evidence_hash_invalid:${riskRef}`);
  addReason(reasons, !hasText(entry?.mitigationTrackerRef), `mitigation_tracker_ref_absent:${riskRef}`);
  addReason(reasons, entry?.escalationRequired === true && !hasText(entry?.escalationRef), `escalation_ref_absent:${riskRef}`);
  addReason(reasons, hlcTuple(entry?.lastReviewedAtHlc) === null, `risk_register_entry_review_time_invalid:${riskRef}`);

  return {
    category: entry?.category,
    controlEvidenceHash: entry?.controlEvidenceHash,
    escalationRef: entry?.escalationRef,
    escalationRequired: entry?.escalationRequired === true,
    initialRiskScore: entry?.initialRiskScore,
    lastReviewedAtHlc: entry?.lastReviewedAtHlc,
    mitigationTrackerRef: entry?.mitigationTrackerRef,
    ownerDid: entry?.ownerDid,
    residualRiskScore: entry?.residualRiskScore,
    riskRef,
    status: entry?.status,
    treatmentPlanHash: entry?.treatmentPlanHash,
  };
}

function evaluateRiskRegister(register, framework, checkedAtHlc, reasons) {
  addReason(reasons, !hasText(register?.registerRef), 'risk_register_ref_absent');
  addReason(reasons, !REGISTER_STATUSES.has(register?.status), 'risk_register_not_current');
  addReason(reasons, !isDigest(register?.registerHash), 'risk_register_hash_invalid');
  addReason(reasons, register?.metadataOnly !== true, 'risk_register_metadata_boundary_invalid');
  addReason(reasons, register?.protectedContentExcluded !== true, 'risk_register_protected_boundary_invalid');
  addReason(reasons, hlcTuple(register?.reviewedAtHlc) === null, 'risk_register_review_time_invalid');
  addReason(reasons, !hlcAfter(register?.reviewedAtHlc, framework?.approvedAtHlc), 'risk_register_review_before_framework_approval');
  addReason(reasons, hlcAfter(register?.reviewedAtHlc, checkedAtHlc), 'risk_register_review_after_check');

  const entries = Array.isArray(register?.entries) ? [...register.entries].sort((left, right) => {
    return String(left?.riskRef ?? '').localeCompare(String(right?.riskRef ?? ''));
  }) : [];
  addReason(reasons, entries.length === 0, 'risk_register_entries_absent');
  const normalizedEntries = entries.map((entry) => evaluateRegisterEntry(entry, reasons));
  const registerCategories = uniqueSorted(
    normalizedEntries
      .filter((entry) => REGISTER_CATEGORIES.has(entry.category) && ENTRY_STATUSES.has(entry.status))
      .map((entry) => entry.category),
  );

  evaluateRequiredSet(
    registerCategories,
    REQUIRED_REGISTER_CATEGORIES,
    REGISTER_CATEGORIES,
    'risk_register_category_missing',
    'risk_register_category_unsupported',
    reasons,
  );

  return { normalizedEntries, registerCategories };
}

function evaluateTraining(program, framework, reasons) {
  addReason(reasons, !hasText(program?.trainingMatrixRef), 'training_matrix_ref_absent');
  addReason(reasons, !isDigest(program?.trainingEvidenceHash), 'training_evidence_hash_invalid');
  addReason(reasons, !isDigest(program?.acknowledgementHash), 'training_acknowledgement_hash_invalid');
  addReason(reasons, program?.metadataOnly !== true, 'training_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(program?.completedAtHlc) === null, 'training_completed_time_invalid');
  addReason(reasons, !hlcAfter(program?.completedAtHlc, framework?.approvedAtHlc), 'training_completed_before_framework_approval');

  const requiredRoles = sortedTextList(program?.requiredRoleRefs);
  addReason(reasons, requiredRoles.length === 0, 'training_required_roles_absent');
  const coverageDomains = sortedTextList(program?.coverageDomains);
  evaluateRequiredSet(
    coverageDomains,
    REQUIRED_TRAINING_DOMAINS,
    TRAINING_DOMAINS,
    'training_domain_missing',
    'training_domain_unsupported',
    reasons,
  );
  return { coverageDomains, requiredRoles };
}

function evaluateSafetyPlanning(safetyPlanning, framework, reasons) {
  addReason(reasons, !hasText(safetyPlanning?.planRef), 'safety_plan_ref_absent');
  addReason(reasons, !isDigest(safetyPlanning?.planHash), 'safety_plan_hash_invalid');
  addReason(reasons, safetyPlanning?.participantSafetyCovered !== true, 'participant_safety_plan_absent');
  addReason(reasons, safetyPlanning?.rightsWellbeingCovered !== true, 'rights_wellbeing_plan_absent');
  addReason(reasons, !isDigest(safetyPlanning?.urgentEscalationPathHash), 'urgent_escalation_path_hash_invalid');
  addReason(reasons, !hasText(safetyPlanning?.medicalReviewOwnerDid), 'medical_review_owner_absent');
  addReason(reasons, safetyPlanning?.metadataOnly !== true, 'safety_plan_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(safetyPlanning?.reviewedAtHlc) === null, 'safety_plan_review_time_invalid');
  addReason(
    reasons,
    !hlcAfter(safetyPlanning?.reviewedAtHlc, framework?.approvedAtHlc),
    'safety_plan_review_before_framework_approval',
  );
}

function evaluateMitigationTracking(tracking, framework, reasons) {
  addReason(reasons, !hasText(tracking?.trackerRef), 'mitigation_tracker_ref_absent');
  addReason(reasons, !isDigest(tracking?.trackerHash), 'mitigation_tracker_hash_invalid');
  addReason(reasons, !isNonNegativeInteger(tracking?.openMitigationCount), 'open_mitigation_count_invalid');
  addReason(reasons, !isNonNegativeInteger(tracking?.overdueMitigationCount), 'overdue_mitigation_count_invalid');
  addReason(reasons, !isNonNegativeInteger(tracking?.unassignedMitigationCount), 'unassigned_mitigation_count_invalid');
  addReason(reasons, !isNonNegativeInteger(tracking?.highRiskWithoutOwnerCount), 'high_risk_without_owner_count_invalid');
  addReason(reasons, tracking?.overdueMitigationCount > 0, 'overdue_mitigations_present');
  addReason(reasons, tracking?.unassignedMitigationCount > 0, 'unassigned_mitigations_present');
  addReason(reasons, tracking?.highRiskWithoutOwnerCount > 0, 'high_risk_without_owner_present');
  addReason(reasons, !isDigest(tracking?.reviewEvidenceHash), 'mitigation_review_evidence_hash_invalid');
  addReason(reasons, tracking?.metadataOnly !== true, 'mitigation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(tracking?.reviewedAtHlc) === null, 'mitigation_review_time_invalid');
  addReason(reasons, !hlcAfter(tracking?.reviewedAtHlc, framework?.approvedAtHlc), 'mitigation_review_before_framework_approval');
}

function evaluateEscalationPath(path, framework, reasons) {
  addReason(reasons, !hasText(path?.pathRef), 'escalation_path_ref_absent');
  addReason(reasons, !isDigest(path?.pathHash), 'escalation_path_hash_invalid');
  addReason(reasons, !isDigest(path?.exerciseEvidenceHash), 'escalation_exercise_evidence_invalid');
  addReason(reasons, path?.metadataOnly !== true, 'escalation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(path?.reviewedAtHlc) === null, 'escalation_review_time_invalid');
  addReason(reasons, !hlcAfter(path?.reviewedAtHlc, framework?.approvedAtHlc), 'escalation_review_before_framework_approval');

  const requiredRoles = sortedTextList(path?.requiredRoleRefs);
  addReason(reasons, !requiredRoles.includes('decision_forum_chair'), 'escalation_role_missing:decision_forum_chair');
  addReason(reasons, !requiredRoles.includes('principal_investigator'), 'escalation_role_missing:principal_investigator');
  addReason(reasons, !requiredRoles.includes('quality_manager'), 'escalation_role_missing:quality_manager');

  const triggers = sortedTextList(path?.decisionForumRequiredFor);
  evaluateRequiredSet(
    triggers,
    REQUIRED_ESCALATION_TRIGGERS,
    ESCALATION_TRIGGERS,
    'escalation_trigger_missing',
    'escalation_trigger_unsupported',
    reasons,
  );
  return requiredRoles;
}

function evaluateHumanGovernance(input, reasons) {
  addReason(reasons, input?.humanGovernance?.verified !== true, 'human_governance_unverified');
  addReason(reasons, !hasText(input?.humanGovernance?.approvedByDid), 'human_approval_absent');
  addReason(reasons, !hasText(input?.humanGovernance?.decisionForumReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.humanGovernance?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, input?.humanGovernance?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, input?.humanGovernance?.openChallenge === true, 'challenge_open');
  addReason(reasons, input?.aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, input?.aiAssistance?.used === true && !isDigest(input?.aiAssistance?.recommendationHash), 'ai_recommendation_hash_invalid');
}

function buildRiskManagementFramework(input, frameworkDomains, registerCategories, normalizedEntries, training, requiredEscalationRoles) {
  const maxResidualRiskScore = normalizedEntries.reduce((max, entry) => {
    return Number.isSafeInteger(entry.residualRiskScore) && entry.residualRiskScore > max ? entry.residualRiskScore : max;
  }, 0);
  const entriesRequiringEscalation = normalizedEntries.filter((entry) => entry.escalationRequired).map((entry) => entry.riskRef).sort();

  const material = {
    schema: FRAMEWORK_SCHEMA,
    tenantId: input?.tenantId ?? '',
    siteId: input?.siteId ?? '',
    frameworkRef: input?.framework?.frameworkRef ?? '',
    policyRef: input?.framework?.policyRef ?? '',
    version: input?.framework?.version ?? '',
    frameworkDomains,
    registerCategories,
    criteriaRef: input?.criteria?.criteriaRef ?? '',
    riskRegisterRef: input?.riskRegister?.registerRef ?? '',
    trainingMatrixRef: input?.trainingProgram?.trainingMatrixRef ?? '',
    safetyPlanRef: input?.safetyPlanning?.planRef ?? '',
    mitigationTrackerRef: input?.mitigationTracking?.trackerRef ?? '',
    escalationPathRef: input?.escalationPath?.pathRef ?? '',
    maxResidualRiskScore,
    entriesRequiringEscalation,
    checkedAtHlc: input?.checkedAtHlc ?? null,
  };
  const frameworkHash = sha256Hex(material);

  return {
    ...material,
    readinessId: `risk_framework_${frameworkHash.slice(0, 32)}`,
    frameworkHash,
    readinessStatus: 'risk_management_framework_ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
    aiFinalAuthority: false,
    frameworkEvidenceHash: input?.framework?.frameworkHash ?? '',
    criteriaHash: input?.criteria?.criteriaHash ?? '',
    riskRegisterHash: input?.riskRegister?.registerHash ?? '',
    trainingCoverageDomains: training.coverageDomains,
    trainingRequiredRoles: training.requiredRoles,
    openMitigationCount: input?.mitigationTracking?.openMitigationCount ?? 0,
    overdueMitigationCount: input?.mitigationTracking?.overdueMitigationCount ?? 0,
    unassignedMitigationCount: input?.mitigationTracking?.unassignedMitigationCount ?? 0,
    highRiskWithoutOwnerCount: input?.mitigationTracking?.highRiskWithoutOwnerCount ?? 0,
    requiredEscalationRoles,
    receiptId: `pending_${frameworkHash.slice(0, 32)}`,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function buildReceipt(input, riskManagementFramework) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did,
    artifactHash: sha256Hex(riskManagementFramework),
    artifactType: 'risk_management_framework',
    artifactVersion: `${input?.framework?.frameworkRef}@${input?.framework?.version}`,
    classification: 'confidential_metadata_only',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.checkedAtHlc,
    sensitivityTags: ['metadata_only', 'policy_16', 'risk_management'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input?.tenantId,
  });
}

export function evaluateRiskManagementFramework(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const frameworkDomains = evaluateFramework(input?.framework, input?.checkedAtHlc, reasons);
  evaluateCriteria(input?.criteria, reasons);
  const { normalizedEntries, registerCategories } = evaluateRiskRegister(
    input?.riskRegister,
    input?.framework,
    input?.checkedAtHlc,
    reasons,
  );
  const training = evaluateTraining(input?.trainingProgram, input?.framework, reasons);
  evaluateSafetyPlanning(input?.safetyPlanning, input?.framework, reasons);
  evaluateMitigationTracking(input?.mitigationTracking, input?.framework, reasons);
  const requiredEscalationRoles = evaluateEscalationPath(input?.escalationPath, input?.framework, reasons);
  evaluateHumanGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const sortedReasons = uniqueReasons(reasons);
  if (sortedReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      trustState: 'inactive',
      exochainProductionClaim: false,
      riskManagementFramework: null,
      receipt: null,
    };
  }

  const riskManagementFramework = buildRiskManagementFramework(
    input,
    frameworkDomains,
    registerCategories,
    normalizedEntries,
    training,
    requiredEscalationRoles,
  );
  const receipt = buildReceipt(input, riskManagementFramework);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
    riskManagementFramework: {
      ...riskManagementFramework,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
