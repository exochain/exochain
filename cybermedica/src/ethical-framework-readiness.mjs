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
const REQUIRED_PERMISSION = 'ethics_framework_review';

const REQUIRED_POLICY_COVERAGE = Object.freeze([
  'anonymous_reporting_process',
  'audit_trail',
  'code_of_conduct',
  'complaint_handling_procedure',
  'concern_reporting_policy',
  'conflict_disclosure_policy',
  'decision_forum_linkage',
  'ethical_statement',
  'escalation_procedure',
  'evidence_requirements',
  'inclusive_leadership_policy',
  'investigation_procedure',
  'no_blame_culture_policy',
  'non_retaliation_policy',
  'recusal_policy',
  'review_cadence',
  'societal_responsibility_statement',
  'training_requirement',
]);

const REQUIRED_TRAINING_ROLES = Object.freeze([
  'coordinator',
  'principal_investigator',
  'quality_manager',
  'site_leader',
]);

const FRAMEWORK_HASH_FIELDS = Object.freeze([
  ['ethicalStatementHash', 'ethical_statement_hash_invalid'],
  ['codeOfConductHash', 'code_of_conduct_hash_invalid'],
  ['societalResponsibilityHash', 'societal_responsibility_hash_invalid'],
  ['inclusiveLeadershipPolicyHash', 'inclusive_leadership_policy_hash_invalid'],
  ['conflictDisclosurePolicyHash', 'conflict_disclosure_policy_hash_invalid'],
  ['recusalPolicyHash', 'recusal_policy_hash_invalid'],
  ['concernReportingPolicyHash', 'concern_reporting_policy_hash_invalid'],
  ['anonymousReportingProcessHash', 'anonymous_reporting_process_hash_invalid'],
  ['nonRetaliationPolicyHash', 'non_retaliation_policy_hash_invalid'],
  ['noBlameCulturePolicyHash', 'no_blame_culture_policy_hash_invalid'],
  ['complaintHandlingProcedureHash', 'complaint_handling_procedure_hash_invalid'],
  ['investigationProcedureHash', 'investigation_procedure_hash_invalid'],
  ['escalationProcedureHash', 'escalation_procedure_hash_invalid'],
  ['decisionForumLinkageHash', 'decision_forum_linkage_hash_invalid'],
  ['trainingRequirementHash', 'training_requirement_hash_invalid'],
  ['evidenceRequirementHash', 'evidence_requirement_hash_invalid'],
  ['auditTrailHash', 'audit_trail_hash_invalid'],
]);

const RAW_ETHICS_FIELDS = new Set([
  'anonymousreportingbody',
  'codeofconductbody',
  'complaintdetails',
  'complaintnarrative',
  'conflictdescription',
  'ethicalstatementtext',
  'ethicsnarrative',
  'investigationnotes',
  'policybody',
  'rawcodeofconduct',
  'rawcomplaint',
  'rawconcern',
  'rawethicalstatement',
  'rawethics',
  'rawethicsnarrative',
  'rawinvestigation',
  'rawpolicytext',
  'rawsocietalresponsibility',
  'retaliationnarrative',
]);

const SECRET_ETHICS_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoEthicsProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoEthicsProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ETHICS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`ethical framework raw content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ETHICS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`ethical framework secret field is not allowed at ${path}.${key}`);
    }
    assertNoEthicsProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoEthicsProtectedContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function addGap(gaps, domain, reason) {
  gaps.push({ domain, reason });
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
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

function afterCheck(checkedAt, value) {
  const tuple = hlcTuple(value);
  return checkedAt !== null && tuple !== null && compareHlc(tuple, checkedAt) > 0;
}

function notAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function checkedPastDue(checkedAt, dueAt) {
  const dueTuple = hlcTuple(dueAt);
  return checkedAt !== null && dueTuple !== null && compareHlc(checkedAt, dueTuple) > 0;
}

function validateBase(input, checkedAt, reasons) {
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, !hasText(input?.siteId), 'site_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(
    reasons,
    input?.actor?.kind === 'ai_agent' || input?.aiAssistance?.finalAuthority === true,
    'ai_final_authority_forbidden',
  );
  addReason(reasons, checkedAt === null, 'checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function validateAuthority(authority, reasons) {
  addReason(reasons, authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function validateReviewCadence(review, checkedAt, reasons) {
  addReason(reasons, review?.status !== 'current', 'framework_review_not_current');
  addReason(reasons, !isDigest(review?.evidenceHash), 'framework_review_evidence_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'framework_review_time_invalid');
  addReason(reasons, hlcTuple(review?.nextReviewDueHlc) === null, 'framework_next_review_time_invalid');
  addReason(reasons, afterCheck(checkedAt, review?.reviewedAtHlc), 'framework_review_after_check');
  addReason(reasons, notAfter(review?.nextReviewDueHlc, review?.reviewedAtHlc), 'framework_next_review_not_after_last');
  addReason(reasons, checkedPastDue(checkedAt, review?.nextReviewDueHlc), 'framework_review_overdue');
}

function validateRequiredCoverage(actualValues, requiredValues, reasons, gaps, reasonPrefix, gapDomain) {
  const actual = new Set(sortedTextList(actualValues));
  for (const required of requiredValues) {
    if (!actual.has(required)) {
      const reason = `${reasonPrefix}:${required}`;
      reasons.push(reason);
      addGap(gaps, gapDomain, reason);
    }
  }
  return requiredValues.filter((required) => actual.has(required));
}

function validateFramework(input, checkedAt, reasons, gaps) {
  const framework = input?.framework;
  if (framework === null || typeof framework !== 'object') {
    reasons.push('ethical_framework_absent');
    addGap(gaps, 'ethical_framework', 'ethical_framework_absent');
    return null;
  }

  addReason(reasons, !hasText(framework.frameworkRef), 'ethical_framework_ref_absent');
  addReason(reasons, !hasText(framework.version), 'ethical_framework_version_absent');
  addReason(reasons, framework.status !== 'approved', 'ethical_framework_not_approved');
  for (const [field, reason] of FRAMEWORK_HASH_FIELDS) {
    addReason(reasons, !isDigest(framework[field]), reason);
  }
  addReason(reasons, sortedTextList(framework.evidenceRefs).length === 0, 'ethical_framework_evidence_refs_absent');
  validateReviewCadence(framework.reviewCadence, checkedAt, reasons);
  return framework;
}

function validateConflictDisclosure(control, reasons) {
  if (control === null || typeof control !== 'object') {
    reasons.push('conflict_disclosure_control_absent');
    return null;
  }
  addReason(reasons, control.active !== true, 'conflict_disclosure_control_inactive');
  addReason(reasons, !hasText(control.policyRef), 'conflict_disclosure_policy_ref_absent');
  addReason(reasons, !isDigest(control.evidenceHash), 'conflict_disclosure_control_evidence_hash_invalid');
  return control.policyRef;
}

function validateRecusal(control, reasons) {
  if (control === null || typeof control !== 'object') {
    reasons.push('recusal_control_absent');
    return null;
  }
  addReason(reasons, control.active !== true, 'recusal_control_inactive');
  addReason(reasons, !hasText(control.policyRef), 'recusal_policy_ref_absent');
  addReason(reasons, !isDigest(control.evidenceHash), 'recusal_control_evidence_hash_invalid');
  return control.policyRef;
}

function validateConcernReporting(control, reasons) {
  if (control === null || typeof control !== 'object') {
    reasons.push('concern_reporting_control_absent');
    return null;
  }
  addReason(reasons, control.active !== true, 'concern_reporting_control_inactive');
  addReason(reasons, !hasText(control.procedureRef), 'concern_reporting_procedure_ref_absent');
  addReason(reasons, control.anonymousEnabled !== true, 'concern_reporting_anonymous_channel_absent');
  addReason(reasons, control.confidentialEnabled !== true, 'concern_reporting_confidential_channel_absent');
  addReason(reasons, !isDigest(control.nonRetaliationSafeguardHash), 'non_retaliation_safeguard_hash_invalid');
  addReason(reasons, !isDigest(control.noBlameCultureEvidenceHash), 'no_blame_culture_evidence_hash_invalid');
  return control.procedureRef;
}

function validateDecisionForum(control, reasons) {
  if (control === null || typeof control !== 'object') {
    reasons.push('decision_forum_linkage_absent');
    return null;
  }
  addReason(reasons, control.active !== true, 'decision_forum_linkage_inactive');
  addReason(reasons, !hasText(control.linkageRef), 'decision_forum_linkage_ref_absent');
  addReason(reasons, control.materialEthicsRoute !== 'decision_forum', 'decision_forum_material_route_invalid');
  addReason(reasons, !hasText(control.receiptRef), 'decision_forum_receipt_ref_absent');
  return control.linkageRef;
}

function validateTraining(control, reasons, gaps) {
  if (control === null || typeof control !== 'object') {
    reasons.push('ethics_training_absent');
    addGap(gaps, 'ethics_training', 'ethics_training_absent');
    return { ref: null, roleRefs: [] };
  }
  addReason(reasons, control.current !== true, 'ethics_training_not_current');
  addReason(reasons, !hasText(control.trainingMatrixRef), 'ethics_training_matrix_ref_absent');
  addReason(reasons, !isDigest(control.completionEvidenceHash), 'ethics_training_completion_evidence_hash_invalid');
  const roleRefs = validateRequiredCoverage(
    control.requiredRoleRefs,
    REQUIRED_TRAINING_ROLES,
    reasons,
    gaps,
    'ethics_training_role_missing',
    'ethics_training',
  );
  return { ref: control.trainingMatrixRef, roleRefs };
}

function validateLinkedControls(input, reasons, gaps) {
  const controls = input?.linkedControls ?? {};
  const refs = [
    validateConflictDisclosure(controls.conflictDisclosure, reasons),
    validateConcernReporting(controls.concernReporting, reasons),
    validateDecisionForum(controls.decisionForum, reasons),
    validateRecusal(controls.recusal, reasons),
  ].filter(hasText);
  const training = validateTraining(controls.training, reasons, gaps);
  if (hasText(training.ref)) {
    refs.push(training.ref);
  }
  return { linkedControlRefs: refs.sort(), trainingRoleRefs: training.roleRefs };
}

function validateHumanGovernance(input, reasons) {
  const governance = input?.humanGovernance;
  addReason(reasons, governance?.verified !== true, 'human_governance_unverified');
  addReason(reasons, !hasText(governance?.approvedByDid), 'human_governance_approver_absent');
  addReason(reasons, !hasText(governance?.decisionForumReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, governance?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, governance?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, governance?.openChallenge === true, 'challenge_open');
}

function validateAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai?.used !== true) {
    return;
  }
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
}

function collectEvidenceHashes(input) {
  const framework = input.framework ?? {};
  const controls = input.linkedControls ?? {};
  return [
    ...FRAMEWORK_HASH_FIELDS.map(([field]) => framework[field]),
    framework.reviewCadence?.evidenceHash,
    controls.conflictDisclosure?.evidenceHash,
    controls.recusal?.evidenceHash,
    controls.concernReporting?.nonRetaliationSafeguardHash,
    controls.concernReporting?.noBlameCultureEvidenceHash,
    controls.training?.completionEvidenceHash,
    input.aiAssistance?.recommendationHash,
  ].filter(isDigest).sort();
}

function buildEthicalFramework(input, policyCoverage, linkedControlRefs, trainingRoleRefs, receiptId) {
  const evidenceHashes = collectEvidenceHashes(input);
  const material = {
    authorityChainHash: input.authority.authorityChainHash,
    checkedAtHlc: input.checkedAtHlc,
    evidenceHashes,
    frameworkRef: input.framework.frameworkRef,
    frameworkVersion: input.framework.version,
    linkedControlRefs,
    policyCoverage,
    schema: 'cybermedica.ethical_framework_readiness_material.v1',
    siteId: input.siteId,
    tenantId: input.tenantId,
    trainingRoleRefs,
  };
  const frameworkHash = sha256Hex(material);

  return {
    schema: 'cybermedica.ethical_framework_readiness.v1',
    readinessId: `cmef_${frameworkHash.slice(0, 32)}`,
    frameworkHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    checkedAtHlc: input.checkedAtHlc,
    frameworkRef: input.framework.frameworkRef,
    frameworkVersion: input.framework.version,
    policyCoverage,
    linkedControlRefs,
    trainingRoleRefs,
    evidenceHashes,
    authorityChainHash: input.authority.authorityChainHash,
    receiptId,
  };
}

function buildReceipt(input, frameworkHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'ethical_framework_readiness',
    artifactVersion: `${input.siteId}@${input.framework.frameworkRef}@${input.framework.version}`,
    artifactHash: frameworkHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['ethics_framework', 'governance', 'metadata_only', 'policy_4'],
    sourceSystem: 'cybermedica-adjacent-surface',
  });
}

function deniedResult(reasons, gaps) {
  return {
    decision: 'denied',
    failClosed: true,
    reasons: [...new Set(reasons)].sort(),
    gaps,
    trustState: 'inactive',
    exochainProductionClaim: false,
    ethicalFramework: null,
    receipt: null,
  };
}

export function evaluateEthicalFrameworkReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const gaps = [];
  const checkedAt = hlcTuple(input?.checkedAtHlc);

  validateBase(input, checkedAt, reasons);
  validateAuthority(input?.authority, reasons);
  validateFramework(input, checkedAt, reasons, gaps);
  const policyCoverage = validateRequiredCoverage(
    input?.policyCoverage,
    REQUIRED_POLICY_COVERAGE,
    reasons,
    gaps,
    'policy_coverage_missing',
    'ethical_framework',
  );
  const { linkedControlRefs, trainingRoleRefs } = validateLinkedControls(input, reasons, gaps);
  validateHumanGovernance(input, reasons);
  validateAiAssistance(input, reasons);

  if (reasons.length > 0) {
    return deniedResult(reasons, gaps);
  }

  const preliminary = buildEthicalFramework(input, policyCoverage, linkedControlRefs, trainingRoleRefs, null);
  const receipt = buildReceipt(input, preliminary.frameworkHash);
  const ethicalFramework = buildEthicalFramework(
    input,
    policyCoverage,
    linkedControlRefs,
    trainingRoleRefs,
    receipt.receiptId,
  );

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    gaps: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
    ethicalFramework,
    receipt,
  };
}
