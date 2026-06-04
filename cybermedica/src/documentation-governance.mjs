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
const DOCUMENTATION_GOVERNANCE_SCHEMA = 'cybermedica.documentation_governance.v1';
const REQUIRED_PERMISSION = 'documentation_governance';

const REQUIRED_GOVERNANCE_DOMAINS = Object.freeze([
  'approval_authority',
  'audit_trail',
  'author_identity',
  'effective_date',
  'material_decision_forum_review',
  'reviewer_identity',
  'rollback',
  'version_lineage',
]);

const REQUIRED_REQUIREMENT_REFS = Object.freeze(['DOC-007']);
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const APPROVED_VERSION_STATUSES = new Set(['approved_for_effective_use']);
const HUMAN_REVIEW_DECISIONS = new Set(['documentation_governance_accepted_inactive_trust', 'hold_for_documentation_gap']);

const RAW_GOVERNANCE_FIELDS = new Set([
  'body',
  'content',
  'documentationbody',
  'documentationcontent',
  'documentationtext',
  'freetext',
  'freetextnote',
  'manualbody',
  'manualcontent',
  'manualtext',
  'rawapprovalnotes',
  'rawcontent',
  'rawdocumentation',
  'rawdocumentationbody',
  'rawdocumentationcontent',
  'rawgovernancecontent',
  'rawmanual',
  'rawmanualcontent',
  'rawrollbackinstructions',
  'rawsource',
  'rawsourcedata',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_GOVERNANCE_FIELDS = new Set([
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

function assertNoRawDocumentationGovernanceContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDocumentationGovernanceContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_GOVERNANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw documentation governance content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_GOVERNANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`documentation governance secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDocumentationGovernanceContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDocumentationGovernanceContent(input ?? {});
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

function missingValues(required, actual) {
  return required.filter((value) => !actual.includes(value));
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

function evaluateRequiredSet(actual, required, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of required) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !required.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_documentation_governor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'documentation_governance_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredDomains = sortedTextList(policy?.requiredGovernanceDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'documentation_governance_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'documentation_governance_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'documentation_governance_policy_not_active');
  addReason(reasons, policy?.materialChangesRequireDecisionForum !== true, 'material_decision_forum_policy_absent');
  addReason(
    reasons,
    policy?.authorReviewerApproverSeparationRequired !== true,
    'author_reviewer_approver_separation_policy_absent',
  );
  addReason(reasons, policy?.rollbackRequired !== true, 'rollback_policy_absent');
  addReason(reasons, policy?.effectiveDateRequired !== true, 'effective_date_policy_absent');
  addReason(reasons, policy?.auditTrailRequired !== true, 'audit_trail_policy_absent');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'documentation_governance_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'documentation_governance_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'documentation_governance_policy_time_invalid');
  evaluateRequiredSet(
    requiredDomains,
    REQUIRED_GOVERNANCE_DOMAINS,
    'policy_governance_domain_missing',
    'policy_governance_domain_unsupported',
    reasons,
  );
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'documentation_governance_cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'documentation_governance_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'documentation_governance_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'documentation_governance_production_trust_claim_forbidden');

  const opened = hlcTuple(cycle?.openedAtHlc);
  const authored = hlcTuple(cycle?.authoredAtHlc);
  const reviewed = hlcTuple(cycle?.reviewedAtHlc);
  const approved = hlcTuple(cycle?.approvedAtHlc);
  const rollbackTested = hlcTuple(cycle?.rollbackTestedAtHlc);
  const effective = hlcTuple(cycle?.effectiveAtHlc);
  const audit = hlcTuple(cycle?.auditRecordedAtHlc);

  addReason(reasons, opened === null, 'open_time_invalid');
  addReason(reasons, authored === null, 'author_time_invalid');
  addReason(reasons, reviewed === null, 'review_time_invalid');
  addReason(reasons, approved === null, 'approval_time_invalid');
  addReason(reasons, rollbackTested === null, 'rollback_test_time_invalid');
  addReason(reasons, effective === null, 'effective_time_invalid');
  addReason(reasons, audit === null, 'audit_time_invalid');
  addReason(
    reasons,
    hlcTuple(policy?.evaluatedAtHlc) !== null && opened !== null && !hlcAfter(cycle.openedAtHlc, policy.evaluatedAtHlc),
    'open_time_not_after_policy_time',
  );
  addReason(reasons, opened !== null && authored !== null && !hlcAfter(cycle.authoredAtHlc, cycle.openedAtHlc), 'author_time_not_after_open_time');
  addReason(reasons, authored !== null && reviewed !== null && !hlcAfter(cycle.reviewedAtHlc, cycle.authoredAtHlc), 'review_time_not_after_author_time');
  addReason(reasons, reviewed !== null && approved !== null && !hlcAfter(cycle.approvedAtHlc, cycle.reviewedAtHlc), 'approval_time_not_after_review_time');
  addReason(
    reasons,
    approved !== null && rollbackTested !== null && !hlcAfter(cycle.rollbackTestedAtHlc, cycle.approvedAtHlc),
    'rollback_test_time_not_after_approval_time',
  );
  addReason(
    reasons,
    rollbackTested !== null && effective !== null && !hlcAfter(cycle.effectiveAtHlc, cycle.rollbackTestedAtHlc),
    'effective_time_not_after_rollback_test_time',
  );
  addReason(reasons, effective !== null && audit !== null && !hlcAfter(cycle.auditRecordedAtHlc, cycle.effectiveAtHlc), 'audit_time_not_after_effective_time');
}

function evaluateDocumentationVersion(version, policy, reasons) {
  const requirementRefs = sortedTextList(version?.sourceRequirementRefs);
  const separationRequired = policy?.authorReviewerApproverSeparationRequired === true;

  addReason(reasons, !hasText(version?.documentRef), 'document_ref_absent');
  addReason(reasons, !hasText(version?.versionRef), 'version_ref_absent');
  addReason(reasons, !hasText(version?.priorVersionRef), 'prior_version_ref_absent');
  addReason(reasons, !hasText(version?.documentFamily), 'document_family_absent');
  addReason(reasons, !APPROVED_VERSION_STATUSES.has(version?.status), 'documentation_version_status_not_approved');
  addReason(reasons, !hasText(version?.authorDid), 'document_author_absent');
  addReason(reasons, !hasText(version?.reviewerDid), 'document_reviewer_absent');
  addReason(reasons, !hasText(version?.approverDid), 'document_approver_absent');
  addReason(reasons, !hasText(version?.authorRoleRef), 'document_author_role_absent');
  addReason(reasons, !hasText(version?.reviewerRoleRef), 'document_reviewer_role_absent');
  addReason(reasons, !hasText(version?.approverRoleRef), 'document_approver_role_absent');
  addReason(reasons, !isDigest(version?.versionHash), 'version_hash_invalid');
  addReason(reasons, !isDigest(version?.priorVersionHash), 'prior_version_hash_invalid');
  addReason(reasons, !isDigest(version?.changeControlHash), 'change_control_hash_invalid');
  addReason(reasons, !isDigest(version?.effectiveDateEvidenceHash), 'effective_date_evidence_hash_invalid');
  addReason(reasons, !hasText(version?.rollbackVersionRef), 'rollback_version_ref_absent');
  addReason(reasons, !isDigest(version?.rollbackVersionHash), 'rollback_version_hash_invalid');
  addReason(reasons, version?.metadataOnly !== true, 'documentation_version_metadata_boundary_invalid');
  addReason(reasons, version?.protectedContentExcluded !== true, 'documentation_version_protected_boundary_invalid');
  addReason(reasons, version?.productionTrustClaim === true, 'documentation_version_production_trust_claim_forbidden');

  for (const requirementRef of REQUIRED_REQUIREMENT_REFS) {
    addReason(reasons, !requirementRefs.includes(requirementRef), `source_requirement_missing:${requirementRef}`);
  }

  if (separationRequired) {
    addReason(
      reasons,
      hasText(version?.authorDid) && version.authorDid === version?.reviewerDid,
      'author_reviewer_not_separated',
    );
    addReason(
      reasons,
      hasText(version?.reviewerDid) && version.reviewerDid === version?.approverDid,
      'reviewer_approver_not_separated',
    );
    addReason(
      reasons,
      hasText(version?.authorDid) && version.authorDid === version?.approverDid,
      'author_approver_not_separated',
    );
  }

  return requirementRefs;
}

function evaluateGovernanceEvidence(evidence, reasons) {
  const domainsCovered = sortedTextList(evidence?.governanceDomainsCovered);

  addReason(reasons, !isDigest(evidence?.authoringEvidenceHash), 'authoring_evidence_hash_invalid');
  addReason(reasons, !isDigest(evidence?.reviewerEvidenceHash), 'reviewer_evidence_hash_invalid');
  addReason(reasons, !isDigest(evidence?.approverEvidenceHash), 'approver_evidence_hash_invalid');
  addReason(reasons, !isDigest(evidence?.materialityAssessmentHash), 'materiality_assessment_hash_invalid');
  addReason(reasons, !isDigest(evidence?.versionHistoryHash), 'version_history_hash_invalid');
  addReason(reasons, !isDigest(evidence?.auditTrailHash), 'audit_trail_hash_invalid');
  addReason(reasons, !isDigest(evidence?.effectiveDateNoticeHash), 'effective_date_notice_hash_invalid');
  addReason(reasons, !isDigest(evidence?.rollbackPlanHash), 'rollback_plan_hash_invalid');
  addReason(reasons, !isDigest(evidence?.rollbackTestHash), 'rollback_test_hash_invalid');
  addReason(reasons, evidence?.metadataOnly !== true, 'governance_evidence_metadata_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'governance_evidence_protected_boundary_invalid');
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, 'governance_evidence_review_time_invalid');
  evaluateRequiredSet(
    domainsCovered,
    REQUIRED_GOVERNANCE_DOMAINS,
    'governance_domain_missing',
    'governance_domain_unsupported',
    reasons,
  );

  return domainsCovered;
}

function evaluateDecisionForum(version, decisionForum, cycle, reasons) {
  if (version?.materialChange !== true) {
    return false;
  }

  addReason(reasons, decisionForum?.verified !== true, 'material_decision_forum_unverified');
  addReason(reasons, decisionForum?.decision !== 'approved', 'material_decision_forum_not_approved');
  addReason(reasons, decisionForum?.humanGateVerified !== true, 'material_decision_forum_human_gate_unverified');
  addReason(reasons, decisionForum?.quorumStatus !== 'met', 'material_decision_forum_quorum_not_met');
  addReason(reasons, decisionForum?.openChallenge === true, 'material_decision_forum_challenge_open');
  addReason(reasons, !hasText(decisionForum?.matterRef), 'material_decision_forum_matter_ref_absent');
  addReason(reasons, !isDigest(decisionForum?.receiptHash), 'material_decision_forum_receipt_hash_invalid');
  addReason(reasons, decisionForum?.metadataOnly !== true, 'material_decision_forum_metadata_boundary_invalid');
  addReason(reasons, decisionForum?.protectedContentExcluded !== true, 'material_decision_forum_protected_boundary_invalid');
  addReason(reasons, hlcTuple(decisionForum?.decidedAtHlc) === null, 'material_decision_forum_time_invalid');
  addReason(
    reasons,
    hlcTuple(decisionForum?.decidedAtHlc) !== null &&
      hlcTuple(cycle?.reviewedAtHlc) !== null &&
      !hlcAfter(decisionForum.decidedAtHlc, cycle.reviewedAtHlc),
    'material_decision_forum_time_not_after_review_time',
  );
  addReason(
    reasons,
    hlcTuple(decisionForum?.decidedAtHlc) !== null &&
      hlcTuple(cycle?.approvedAtHlc) !== null &&
      !hlcAfter(cycle.approvedAtHlc, decisionForum.decidedAtHlc),
    'approval_time_not_after_decision_forum_time',
  );

  return decisionForum?.verified === true && decisionForum?.decision === 'approved' && isDigest(decisionForum?.receiptHash);
}

function evaluateRollbackControl(rollback, version, cycle, reasons) {
  addReason(reasons, !hasText(rollback?.rollbackPlanRef), 'rollback_plan_ref_absent');
  addReason(reasons, rollback?.rollbackVersionRef !== version?.rollbackVersionRef, 'rollback_version_ref_mismatch');
  addReason(reasons, rollback?.rollbackVersionHash !== version?.rollbackVersionHash, 'rollback_version_hash_mismatch');
  addReason(reasons, !isDigest(rollback?.rollbackRunbookHash), 'rollback_runbook_hash_invalid');
  addReason(reasons, !isDigest(rollback?.disablementPathHash), 'rollback_disablement_path_hash_invalid');
  addReason(reasons, !isDigest(rollback?.accessWithdrawalHash), 'rollback_access_withdrawal_hash_invalid');
  addReason(reasons, rollback?.tested !== true, 'rollback_test_absent');
  addReason(reasons, hlcTuple(rollback?.testedAtHlc) === null, 'rollback_control_test_time_invalid');
  addReason(
    reasons,
    hlcTuple(rollback?.testedAtHlc) !== null &&
      hlcTuple(cycle?.approvedAtHlc) !== null &&
      !hlcAfter(rollback.testedAtHlc, cycle.approvedAtHlc),
    'rollback_control_test_time_not_after_approval_time',
  );
  addReason(
    reasons,
    hlcTuple(rollback?.testedAtHlc) !== null &&
      hlcTuple(cycle?.effectiveAtHlc) !== null &&
      !hlcAfter(cycle.effectiveAtHlc, rollback.testedAtHlc),
    'effective_time_not_after_rollback_control_test_time',
  );
  addReason(reasons, rollback?.metadataOnly !== true, 'rollback_control_metadata_boundary_invalid');
  addReason(reasons, rollback?.protectedContentExcluded !== true, 'rollback_control_protected_boundary_invalid');
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);

  addReason(reasons, !commandRefs.includes('npm run quality'), 'quality_gate_command_missing');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validation?.docsUpdated !== true, 'documentation_updates_absent');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_readonly_evidence_boundary_invalid');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_recorded_time_invalid');
  addReason(
    reasons,
    hlcTuple(validation?.recordedAtHlc) !== null &&
      hlcTuple(cycle?.effectiveAtHlc) !== null &&
      !hlcAfter(validation.recordedAtHlc, cycle.effectiveAtHlc),
    'validation_time_not_after_effective_time',
  );
  addReason(reasons, validation?.metadataOnly !== true, 'validation_evidence_metadata_boundary_invalid');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_role_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcTuple(review?.reviewedAtHlc) !== null &&
      hlcTuple(cycle?.effectiveAtHlc) !== null &&
      !hlcAfter(review.reviewedAtHlc, cycle.effectiveAtHlc),
    'human_review_time_not_after_effective_time',
  );
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return false;
  }

  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).length === 0, 'ai_limitation_hash_absent');
  for (const limitationHash of sortedTextList(aiAssistance.limitationHashes)) {
    addReason(reasons, !isDigest(limitationHash), `ai_limitation_hash_invalid:${limitationHash}`);
  }
  return true;
}

function createDocumentationGovernanceDigest(input, governanceDomains, sourceRequirementRefs) {
  return sha256Hex({
    approverDid: input?.documentationVersion?.approverDid ?? null,
    auditTrailHash: input?.governanceEvidence?.auditTrailHash ?? null,
    authorDid: input?.documentationVersion?.authorDid ?? null,
    changeControlHash: input?.documentationVersion?.changeControlHash ?? null,
    cycleRef: input?.governanceCycle?.cycleRef ?? null,
    documentRef: input?.documentationVersion?.documentRef ?? null,
    effectiveAtHlc: input?.governanceCycle?.effectiveAtHlc ?? null,
    effectiveDateEvidenceHash: input?.documentationVersion?.effectiveDateEvidenceHash ?? null,
    governanceDomains,
    priorVersionHash: input?.documentationVersion?.priorVersionHash ?? null,
    reviewerDid: input?.documentationVersion?.reviewerDid ?? null,
    rollbackPlanHash: input?.governanceEvidence?.rollbackPlanHash ?? null,
    rollbackVersionHash: input?.documentationVersion?.rollbackVersionHash ?? null,
    sourceRequirementRefs,
    tenantId: input?.tenantId ?? null,
    versionHash: input?.documentationVersion?.versionHash ?? null,
    versionRef: input?.documentationVersion?.versionRef ?? null,
  });
}

function createDocumentationGovernanceSummary(
  input,
  reasons,
  governanceDomains,
  sourceRequirementRefs,
  materialDecisionForumLinked,
  aiAssistanceUsed,
  digest,
) {
  return {
    schema: DOCUMENTATION_GOVERNANCE_SCHEMA,
    documentationGovernanceId: `cmdg_${digest.slice(0, 32)}`,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.governanceCycle?.cycleRef ?? null,
    documentRef: input?.documentationVersion?.documentRef ?? null,
    versionRef: input?.documentationVersion?.versionRef ?? null,
    priorVersionRef: input?.documentationVersion?.priorVersionRef ?? null,
    documentFamily: input?.documentationVersion?.documentFamily ?? null,
    status: reasons.length === 0 ? 'approved_for_effective_use' : 'denied',
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    doc007Satisfied: reasons.length === 0 && sourceRequirementRefs.includes('DOC-007'),
    effectiveForUse: reasons.length === 0,
    rollbackAvailable: reasons.length === 0,
    materialChange: input?.documentationVersion?.materialChange === true,
    materialDecisionForumLinked,
    aiAssistanceUsed,
    authorDid: input?.documentationVersion?.authorDid ?? null,
    reviewerDid: input?.documentationVersion?.reviewerDid ?? null,
    approverDid: input?.documentationVersion?.approverDid ?? null,
    effectiveAtHlc: input?.governanceCycle?.effectiveAtHlc ?? null,
    rollbackVersionRef: input?.documentationVersion?.rollbackVersionRef ?? null,
    rollbackVersionHash: input?.documentationVersion?.rollbackVersionHash ?? null,
    governanceDomains,
    missingGovernanceDomains: missingValues(REQUIRED_GOVERNANCE_DOMAINS, governanceDomains),
    sourceRequirementRefs,
    documentationGovernanceDigest: digest,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#DOC-007',
      'cyber_medica_qms_prd_master.md#FR-031',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export function evaluateDocumentationGovernance(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.governancePolicy, reasons);
  evaluateCycle(input?.governanceCycle, input?.governancePolicy, reasons);
  const sourceRequirementRefs = evaluateDocumentationVersion(input?.documentationVersion, input?.governancePolicy, reasons);
  const governanceDomains = evaluateGovernanceEvidence(input?.governanceEvidence, reasons);
  const materialDecisionForumLinked = evaluateDecisionForum(
    input?.documentationVersion,
    input?.decisionForum,
    input?.governanceCycle,
    reasons,
  );
  evaluateRollbackControl(input?.rollbackControl, input?.documentationVersion, input?.governanceCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.governanceCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.governanceCycle, reasons);
  const aiAssistanceUsed = evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  const documentationGovernanceDigest = createDocumentationGovernanceDigest(
    input,
    governanceDomains,
    sourceRequirementRefs,
  );
  const documentationGovernance = createDocumentationGovernanceSummary(
    input,
    finalReasons,
    governanceDomains,
    sourceRequirementRefs,
    materialDecisionForumLinked,
    aiAssistanceUsed,
    documentationGovernanceDigest,
  );

  if (finalReasons.length > 0) {
    return {
      schema: 'cybermedica.documentation_governance_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      documentationGovernance,
      receipt: null,
    };
  }

  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'documentation_governance',
    artifactVersion: `${input.documentationVersion.documentRef}@${input.documentationVersion.versionRef}`,
    artifactHash: documentationGovernanceDigest,
    classification: 'metadata_only_documentation_governance',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.governanceCycle.effectiveAtHlc,
    sensitivityTags: [
      'doc_007',
      'documentation_governance_metadata',
      'effective_date_metadata',
      'no_raw_content',
      'rollback_metadata',
      'version_lineage_metadata',
    ],
    sourceSystem: 'cybermedica',
  });

  return {
    schema: 'cybermedica.documentation_governance_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    documentationGovernance,
    receipt,
  };
}
