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
const REQUIRED_PERMISSION = 'cqi_manage';
const CQI_SCHEMA = 'cybermedica.continuous_quality_improvement.v1';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_SOURCE_FAMILIES = Object.freeze([
  'analysis',
  'audit',
  'complaint',
  'innovation_project',
  'internal_audit',
  'lessons_learned',
  'nonconformity',
  'self_assessment',
  'staff_feedback',
  'stakeholder_feedback',
  'training',
]);

const SUPPORTED_SOURCE_FAMILIES = new Set([
  ...REQUIRED_SOURCE_FAMILIES,
  'capa',
  'deviation',
  'kpi_trend',
  'quality_objective',
  'risk_assessment',
]);

const REQUIRED_IMPACT_DOMAINS = Object.freeze([
  'budget',
  'sop',
  'stakeholder',
  'technology',
  'training',
]);

const REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES = Object.freeze([
  'accessibility_barrier',
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
]);

const REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES = Object.freeze([
  'cqi_review',
  'documentation_update',
  'manual_crosslink_refresh',
  'system_change',
  'training_update',
  'workflow_change',
]);

const POLICY_STATUSES = new Set(['active']);
const CLOSURE_STATUSES = new Set(['closed_effective', 'closed_follow_up']);
const EFFECTIVENESS_STATUSES = new Set(['effective', 'follow_up_scheduled']);
const HUMAN_REVIEW_DECISIONS = new Set(['cqi_closed_effective', 'cqi_follow_up_scheduled']);
const RISK_LEVELS = new Set(['standard', 'major', 'critical']);

const RAW_CQI_FIELDS = new Set([
  'complaintdetails',
  'complaintnarrative',
  'effectivenessnotes',
  'feedbacktext',
  'freeformanalysis',
  'improvementnarrative',
  'lessonslearnedtext',
  'problemstatement',
  'proposedchange',
  'rawcomplaint',
  'rawcqi',
  'rawimprovement',
  'rawlesson',
  'rawnonconformity',
  'rawproblemstatement',
  'rawsource',
  'rawstafffeedback',
  'rawstakeholderfeedback',
  'reviewnotes',
  'rootcauseanalysis',
  'sourcepayload',
  'stakeholdercomment',
]);

const SECRET_CQI_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawCqiContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawCqiContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CQI_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw CQI content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CQI_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`CQI secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawCqiContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawCqiContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.siteId), 'site_id_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'cqi_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  const requiredSourceFamilies = sortedTextList(policy?.requiredSourceFamilies);
  const requiredImpactDomains = sortedTextList(policy?.requiredImpactDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'cqi_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'cqi_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'cqi_policy_not_active');
  addReason(reasons, policy?.decisionForumMaterialityRequired !== true, 'cqi_policy_materiality_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'cqi_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'cqi_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'cqi_policy_evaluated_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'cqi_policy_evaluated_after_check');

  for (const family of REQUIRED_SOURCE_FAMILIES) {
    addReason(reasons, !requiredSourceFamilies.includes(family), `cqi_policy_source_family_missing:${family}`);
  }
  for (const domain of REQUIRED_IMPACT_DOMAINS) {
    addReason(reasons, !requiredImpactDomains.includes(domain), `cqi_policy_impact_domain_missing:${domain}`);
  }

  return { requiredImpactDomains, requiredSourceFamilies };
}

function evaluateImprovement(improvement, reasons) {
  const relatedControlRefs = sortedTextList(improvement?.relatedControlRefs);
  const relatedProcessRefs = sortedTextList(improvement?.relatedProcessRefs);
  const relatedRiskRefs = sortedTextList(improvement?.relatedRiskRefs);
  const relatedDeviationRefs = sortedTextList(improvement?.relatedDeviationRefs);
  const relatedComplaintRefs = sortedTextList(improvement?.relatedComplaintRefs);
  const requiredResourceRefs = sortedTextList(improvement?.requiredResourceRefs);
  const evidenceRequirementRefs = sortedTextList(improvement?.evidenceRequirementRefs);

  addReason(reasons, !hasText(improvement?.improvementId), 'improvement_id_absent');
  addReason(reasons, !hasText(improvement?.improvementSource), 'improvement_source_absent');
  addReason(reasons, !isDigest(improvement?.problemStatementHash), 'problem_statement_hash_invalid');
  addReason(reasons, relatedControlRefs.length === 0, 'related_control_refs_absent');
  addReason(reasons, relatedProcessRefs.length === 0, 'related_process_refs_absent');
  addReason(reasons, relatedRiskRefs.length === 0, 'related_risk_refs_absent');
  addReason(reasons, relatedDeviationRefs.length === 0, 'related_deviation_refs_absent');
  addReason(reasons, relatedComplaintRefs.length === 0, 'related_complaint_refs_absent');
  addReason(reasons, !isDigest(improvement?.rootCauseAnalysisHash), 'root_cause_analysis_hash_invalid');
  addReason(reasons, !isDigest(improvement?.proposedChangeHash), 'proposed_change_hash_invalid');
  addReason(reasons, !isDigest(improvement?.expectedBenefitHash), 'expected_benefit_hash_invalid');
  addReason(reasons, !isDigest(improvement?.potentialRiskHash), 'potential_risk_hash_invalid');
  addReason(reasons, requiredResourceRefs.length === 0, 'required_resource_refs_absent');
  addReason(reasons, !hasText(improvement?.ownerDid), 'improvement_owner_absent');
  addReason(reasons, !hasText(improvement?.approverDid), 'improvement_approver_absent');
  addReason(reasons, !isDigest(improvement?.implementationPlanHash), 'implementation_plan_hash_invalid');
  addReason(reasons, hlcTuple(improvement?.dueAtHlc) === null, 'improvement_due_time_invalid');
  addReason(reasons, !isDigest(improvement?.trainingImpactHash), 'training_impact_hash_invalid');
  addReason(reasons, !isDigest(improvement?.sopImpactHash), 'sop_impact_hash_invalid');
  addReason(reasons, !isDigest(improvement?.technologyImpactHash), 'technology_impact_hash_invalid');
  addReason(reasons, !isDigest(improvement?.budgetImpactHash), 'budget_impact_hash_invalid');
  addReason(reasons, !isDigest(improvement?.stakeholderImpactHash), 'stakeholder_impact_hash_invalid');
  addReason(reasons, evidenceRequirementRefs.length === 0, 'evidence_requirement_refs_absent');
  addReason(reasons, !isDigest(improvement?.verificationMethodHash), 'verification_method_hash_invalid');
  addReason(reasons, !isDigest(improvement?.effectivenessCheckHash), 'effectiveness_check_hash_invalid');
  addReason(reasons, !hasText(improvement?.decisionForumMatterRef), 'decision_forum_matter_ref_absent');
  addReason(reasons, !CLOSURE_STATUSES.has(improvement?.closureStatus), 'closure_status_invalid');
  addReason(reasons, !isDigest(improvement?.lessonsLearnedHash), 'lessons_learned_hash_invalid');
  addReason(reasons, improvement?.metadataOnly !== true, 'improvement_metadata_boundary_invalid');
  addReason(reasons, improvement?.protectedContentExcluded !== true, 'improvement_protected_boundary_invalid');
  addReason(reasons, improvement?.exochainProductionClaim !== false, 'production_trust_claim_forbidden');

  return {
    evidenceRequirementRefs,
    relatedComplaintRefs,
    relatedControlRefs,
    relatedDeviationRefs,
    relatedProcessRefs,
    relatedRiskRefs,
    requiredResourceRefs,
  };
}

function sourceLabel(source, index) {
  return hasText(source?.sourceRef) ? source.sourceRef : `index_${index}`;
}

function evaluateSources(sources, requiredSourceFamilies, checkedAtHlc, reasons) {
  const rows = Array.isArray(sources) ? [...sources] : [];
  const sourceFamilies = [];
  const sourceRefs = new Set();

  addReason(reasons, rows.length === 0, 'cqi_sources_absent');

  rows.forEach((source, index) => {
    const label = sourceLabel(source, index);
    addReason(reasons, !hasText(source?.sourceRef), `cqi_source_ref_absent:${label}`);
    addReason(reasons, sourceRefs.has(source?.sourceRef), `cqi_source_ref_duplicate:${label}`);
    if (hasText(source?.sourceRef)) {
      sourceRefs.add(source.sourceRef);
    }
    addReason(reasons, !SUPPORTED_SOURCE_FAMILIES.has(source?.sourceFamily), `cqi_source_family_unsupported:${label}`);
    addReason(reasons, !isDigest(source?.sourceHash), `cqi_source_hash_invalid:${label}`);
    addReason(reasons, hlcTuple(source?.capturedAtHlc) === null, `cqi_source_time_invalid:${label}`);
    addReason(reasons, hlcAfter(source?.capturedAtHlc, checkedAtHlc), `cqi_source_after_check:${label}`);
    addReason(reasons, source?.reviewedByHuman !== true, `cqi_source_human_review_absent:${label}`);
    addReason(reasons, source?.metadataOnly !== true, `cqi_source_metadata_boundary_invalid:${label}`);
    addReason(reasons, source?.protectedContentExcluded !== true, `cqi_source_protected_boundary_invalid:${label}`);
    addReason(reasons, sortedTextList(source?.relatedEvidenceRefs).length === 0, `cqi_source_evidence_refs_absent:${label}`);
    if (hasText(source?.sourceFamily)) {
      sourceFamilies.push(source.sourceFamily);
    }
  });

  const uniqueSourceFamilies = uniqueSorted(sourceFamilies);
  for (const family of requiredSourceFamilies) {
    addReason(reasons, !uniqueSourceFamilies.includes(family), `cqi_source_family_missing:${family}`);
  }

  return uniqueSourceFamilies;
}

function evaluateImpactAssessment(impact, requiredImpactDomains, checkedAtHlc, reasons) {
  const impactDomains = sortedTextList(impact?.domains);

  addReason(reasons, impactDomains.length === 0, 'impact_domains_absent');
  for (const domain of requiredImpactDomains) {
    addReason(reasons, !impactDomains.includes(domain), `impact_domain_missing:${domain}`);
  }
  addReason(reasons, !RISK_LEVELS.has(impact?.riskLevel), 'impact_risk_level_invalid');
  addReason(reasons, !isDigest(impact?.mitigationEvidenceHash), 'impact_mitigation_evidence_hash_invalid');
  addReason(reasons, hlcTuple(impact?.assessedAtHlc) === null, 'impact_assessed_time_invalid');
  addReason(reasons, hlcAfter(impact?.assessedAtHlc, checkedAtHlc), 'impact_assessed_after_check');
  addReason(reasons, impact?.metadataOnly !== true, 'impact_metadata_boundary_invalid');

  const material =
    impact?.riskLevel === 'critical' ||
    impact?.participantSafetyImpact === true ||
    impact?.dataIntegrityImpact === true ||
    impact?.sponsorCroImpact === true;

  return { impactDomains, material };
}

function evaluateImplementationPlan(plan, improvement, reasons) {
  const taskRefs = sortedTextList(plan?.taskRefs);
  const trainingUpdateRefs = sortedTextList(plan?.trainingUpdateRefs);
  const sopUpdateRefs = sortedTextList(plan?.sopUpdateRefs);
  const technologyChangeRefs = sortedTextList(plan?.technologyChangeRefs);

  addReason(reasons, hlcTuple(plan?.approvedAtHlc) === null, 'implementation_approved_time_invalid');
  addReason(reasons, hlcTuple(plan?.implementedAtHlc) === null, 'implementation_time_invalid');
  addReason(reasons, taskRefs.length === 0, 'implementation_task_refs_absent');
  addReason(reasons, !isDigest(plan?.resourcePlanHash), 'implementation_resource_plan_hash_invalid');
  addReason(reasons, plan?.ownerAccepted !== true, 'implementation_owner_acceptance_absent');
  addReason(reasons, plan?.approverApproved !== true, 'implementation_approver_approval_absent');
  addReason(reasons, plan?.metadataOnly !== true, 'implementation_metadata_boundary_invalid');
  addReason(reasons, trainingUpdateRefs.length === 0 && isDigest(improvement?.trainingImpactHash), 'training_impact_without_update_ref');
  addReason(reasons, sopUpdateRefs.length === 0 && isDigest(improvement?.sopImpactHash), 'sop_impact_without_update_ref');
  addReason(reasons, technologyChangeRefs.length === 0 && isDigest(improvement?.technologyImpactHash), 'technology_impact_without_change_ref');
  addReason(reasons, !isDigest(plan?.budgetReviewHash) && isDigest(improvement?.budgetImpactHash), 'budget_impact_without_review_hash');
  addReason(reasons, hlcBefore(improvement?.dueAtHlc, plan?.approvedAtHlc), 'improvement_due_before_approval');
  addReason(reasons, hlcBefore(plan?.implementedAtHlc, plan?.approvedAtHlc), 'implementation_before_approval');

  return {
    sopUpdateRefs,
    taskRefs,
    technologyChangeRefs,
    trainingUpdateRefs,
  };
}

function evaluateEffectivenessCheck(effectiveness, implementationPlan, reasons) {
  addReason(reasons, hlcTuple(effectiveness?.checkedAtHlc) === null, 'effectiveness_time_invalid');
  addReason(reasons, !EFFECTIVENESS_STATUSES.has(effectiveness?.status), 'effectiveness_status_invalid');
  addReason(reasons, !isDigest(effectiveness?.verificationEvidenceHash), 'effectiveness_evidence_hash_invalid');
  addReason(reasons, effectiveness?.expectedBenefitMet !== true, 'effectiveness_expected_benefit_unmet');
  addReason(reasons, effectiveness?.recurrenceObserved === true, 'effectiveness_recurrence_observed');
  addReason(reasons, effectiveness?.followUpRequired === true && !isDigest(effectiveness?.followUpPlanHash), 'effectiveness_follow_up_plan_absent');
  addReason(reasons, !isBasisPoints(effectiveness?.residualRiskBasisPoints), 'residual_risk_basis_points_invalid');
  addReason(reasons, !hasText(effectiveness?.reviewerDid), 'effectiveness_reviewer_absent');
  addReason(reasons, effectiveness?.metadataOnly !== true, 'effectiveness_metadata_boundary_invalid');
  addReason(reasons, hlcNotAfter(effectiveness?.checkedAtHlc, implementationPlan?.implementedAtHlc), 'effectiveness_before_implementation');
}

function evaluateInquiryCqiBacklog(backlog, implementationPlan, reasons) {
  const sourceFamilies = sortedTextList(backlog?.sourceFamilies);
  const improvementCategories = sortedTextList(backlog?.improvementCategories);
  const linkedBacklogItemRefs = sortedTextList(backlog?.linkedBacklogItemRefs);
  const cqiRequiredSignalRefs = sortedTextList(backlog?.cqiRequiredSignalRefs);
  const driftSignalRefs = sortedTextList(backlog?.driftSignalRefs);

  addReason(reasons, !isDigest(backlog?.receiptHash), 'inquiry_cqi_backlog_receipt_hash_invalid');
  addReason(reasons, !isDigest(backlog?.backlogDigest), 'inquiry_cqi_backlog_digest_invalid');
  addReason(reasons, backlog?.ready !== true, 'inquiry_cqi_backlog_not_ready');
  addReason(reasons, backlog?.trustState !== 'inactive', 'inquiry_cqi_backlog_trust_state_invalid');
  addReason(reasons, backlog?.exochainProductionClaim !== false, 'inquiry_cqi_backlog_production_claim_forbidden');
  addReason(reasons, backlog?.metadataOnly !== true, 'inquiry_cqi_backlog_metadata_boundary_invalid');
  addReason(reasons, backlog?.protectedContentExcluded !== true, 'inquiry_cqi_backlog_protected_boundary_invalid');

  for (const family of REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES) {
    addReason(reasons, !sourceFamilies.includes(family), `inquiry_cqi_backlog_source_family_missing:${family}`);
  }
  for (const category of REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES) {
    addReason(
      reasons,
      !improvementCategories.includes(category),
      `inquiry_cqi_backlog_improvement_category_missing:${category}`,
    );
  }

  addReason(reasons, linkedBacklogItemRefs.length === 0, 'inquiry_cqi_backlog_item_refs_absent');
  addReason(reasons, cqiRequiredSignalRefs.length === 0, 'inquiry_cqi_backlog_cqi_signal_refs_absent');
  addReason(reasons, driftSignalRefs.length === 0, 'inquiry_cqi_backlog_drift_signal_refs_absent');
  addReason(reasons, !isDigest(backlog?.userAssistanceReceiptHash), 'inquiry_cqi_backlog_user_assistance_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(backlog?.userAssistanceAnalyticsDigest),
    'inquiry_cqi_backlog_user_assistance_analytics_digest_invalid',
  );
  addReason(reasons, !isDigest(backlog?.contextualManualDrawerHash), 'inquiry_cqi_backlog_manual_drawer_hash_invalid');
  addReason(
    reasons,
    !isDigest(backlog?.contextualManualDrawerReceiptHash),
    'inquiry_cqi_backlog_manual_drawer_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(backlog?.controlledDocumentDistributionReceiptHash),
    'inquiry_cqi_backlog_distribution_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(backlog?.documentationPublicationReceiptHash),
    'inquiry_cqi_backlog_publication_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(backlog?.manualExportReceiptHash),
    'inquiry_cqi_backlog_manual_export_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(backlog?.roleManualCoverageReceiptHash),
    'inquiry_cqi_backlog_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(backlog?.acknowledgementRosterHash),
    'inquiry_cqi_backlog_acknowledgement_roster_hash_invalid',
  );
  addReason(reasons, backlog?.manualNavigationReady !== true, 'inquiry_cqi_backlog_manual_navigation_ready_absent');
  addReason(reasons, backlog?.manualNavigationEffectiveUseAcknowledged !== true, 'inquiry_cqi_backlog_effective_use_absent');
  addReason(
    reasons,
    backlog?.manualNavigationCurrentVersionOnly !== true,
    'inquiry_cqi_backlog_current_version_boundary_invalid',
  );
  addReason(
    reasons,
    backlog?.manualNavigationObsoleteVersionUseBlocked !== true,
    'inquiry_cqi_backlog_obsolete_version_boundary_invalid',
  );
  addReason(reasons, hlcTuple(backlog?.reviewedAtHlc) === null, 'inquiry_cqi_backlog_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(backlog?.reviewedAtHlc, implementationPlan?.approvedAtHlc),
    'inquiry_cqi_backlog_review_after_implementation_approval',
  );

  return {
    acknowledgementRosterHash: backlog?.acknowledgementRosterHash ?? null,
    cqiRequiredSignalRefs,
    driftSignalRefs,
    improvementCategories,
    linkedBacklogItemRefs,
    manualNavigationCurrentVersionOnly: backlog?.manualNavigationCurrentVersionOnly === true,
    manualNavigationEffectiveUseAcknowledged: backlog?.manualNavigationEffectiveUseAcknowledged === true,
    manualNavigationObsoleteVersionUseBlocked: backlog?.manualNavigationObsoleteVersionUseBlocked === true,
    manualNavigationReady: backlog?.manualNavigationReady === true,
    receiptHash: backlog?.receiptHash ?? null,
    backlogDigest: backlog?.backlogDigest ?? null,
    roleManualCoverageReceiptHash: backlog?.roleManualCoverageReceiptHash ?? null,
    sourceFamilies,
  };
}

function evaluateDecisionForum(decisionForum, improvement, material, reasons) {
  if (material) {
    addReason(reasons, decisionForum?.invoked !== true, 'material_cqi_decision_forum_required');
  }
  if (decisionForum?.invoked === true || material) {
    addReason(reasons, !hasText(decisionForum?.matterRef), 'decision_forum_matter_absent');
    addReason(reasons, decisionForum?.matterRef !== improvement?.decisionForumMatterRef, 'decision_forum_matter_mismatch');
    addReason(reasons, !hasText(decisionForum?.receiptId), 'decision_forum_receipt_absent');
    addReason(reasons, decisionForum?.quorumStatus !== 'met', 'decision_forum_quorum_not_met');
    addReason(reasons, decisionForum?.humanGateVerified !== true, 'decision_forum_human_gate_unverified');
    addReason(reasons, decisionForum?.openChallenge === true, 'decision_forum_open_challenge');
    addReason(reasons, hlcTuple(decisionForum?.decidedAtHlc) === null, 'decision_forum_decided_time_invalid');
  }
}

function evaluateHumanReview(humanReview, improvement, effectiveness, reasons) {
  addReason(reasons, humanReview?.verified !== true, 'human_review_unverified');
  addReason(reasons, !hasText(humanReview?.reviewedByDid), 'human_review_did_absent');
  addReason(reasons, !isDigest(humanReview?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(
    reasons,
    improvement?.closureStatus === 'closed_effective' && humanReview?.decision !== 'cqi_closed_effective',
    'human_review_closure_mismatch',
  );
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcNotAfter(humanReview?.reviewedAtHlc, effectiveness?.checkedAtHlc), 'human_review_before_effectiveness');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used === false) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance?.advisoryOnly !== true, 'ai_advisory_boundary_invalid');
  addReason(reasons, !isDigest(aiAssistance?.promptHash), 'ai_prompt_hash_invalid');
  addReason(reasons, !isDigest(aiAssistance?.outputHash), 'ai_output_hash_invalid');
  addReason(reasons, aiAssistance?.humanReviewed !== true, 'ai_human_review_absent');
}

function evaluateAuditRecord(auditRecord, humanReview, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'cqi_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'cqi_audit_record_hash_invalid');
  addReason(reasons, hlcTuple(auditRecord?.recordedAtHlc) === null, 'cqi_audit_record_time_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'cqi_audit_record_metadata_boundary_invalid');
  addReason(reasons, hlcNotAfter(auditRecord?.recordedAtHlc, humanReview?.reviewedAtHlc), 'audit_record_before_human_review');
}

function buildCycleMaterial(input, normalized) {
  return {
    actorDid: input.actor?.did,
    auditRecordHash: input.auditRecord?.auditRecordHash,
    budgetImpactHash: input.improvement?.budgetImpactHash,
    closureStatus: input.improvement?.closureStatus,
    cqiPolicyHash: input.cqiPolicy?.policyHash,
    decisionForumMatterRef: input.decisionForum?.matterRef,
    effectivenessEvidenceHash: input.effectivenessCheck?.verificationEvidenceHash,
    improvementId: input.improvement?.improvementId,
    implementationPlanHash: input.improvement?.implementationPlanHash,
    impactDomains: normalized.impactDomains,
    inquiryCqiBacklogDigest: normalized.inquiryCqiBacklog.backlogDigest,
    inquiryCqiBacklogImprovementCategories: normalized.inquiryCqiBacklog.improvementCategories,
    inquiryCqiBacklogLinkedItemRefs: normalized.inquiryCqiBacklog.linkedBacklogItemRefs,
    inquiryCqiBacklogReceiptHash: normalized.inquiryCqiBacklog.receiptHash,
    inquiryCqiBacklogSourceFamilies: normalized.inquiryCqiBacklog.sourceFamilies,
    inquiryCqiBacklogSignalRefs: normalized.inquiryCqiBacklog.cqiRequiredSignalRefs,
    manualNavigationEffectiveUseAcknowledged: normalized.inquiryCqiBacklog.manualNavigationEffectiveUseAcknowledged,
    manualNavigationReady: normalized.inquiryCqiBacklog.manualNavigationReady,
    lessonsLearnedHash: input.improvement?.lessonsLearnedHash,
    relatedComplaintRefs: normalized.improvement.relatedComplaintRefs,
    relatedControlRefs: normalized.improvement.relatedControlRefs,
    relatedDeviationRefs: normalized.improvement.relatedDeviationRefs,
    relatedProcessRefs: normalized.improvement.relatedProcessRefs,
    relatedRiskRefs: normalized.improvement.relatedRiskRefs,
    requiredResourceRefs: normalized.improvement.requiredResourceRefs,
    schema: CQI_SCHEMA,
    siteId: input.siteId,
    sourceFamilies: normalized.sourceFamilies,
    tenantId: input.tenantId,
  };
}

function buildCycle(input, cycleHash, normalized, material) {
  return {
    schema: CQI_SCHEMA,
    cqiCycleId: `cmcqi_${cycleHash.slice(0, 32)}`,
    cycleHash,
    improvementId: input.improvement?.improvementId ?? null,
    status: input.improvement?.closureStatus ?? 'hold_for_cqi_gap',
    materialDecisionForumRequired: material,
    sourceFamilies: normalized.sourceFamilies,
    impactDomains: normalized.impactDomains,
    inquiryCqiBacklogDigest: normalized.inquiryCqiBacklog.backlogDigest,
    inquiryCqiBacklogImprovementCategories: normalized.inquiryCqiBacklog.improvementCategories,
    inquiryCqiBacklogReceiptHash: normalized.inquiryCqiBacklog.receiptHash,
    inquiryCqiBacklogSourceFamilies: normalized.inquiryCqiBacklog.sourceFamilies,
    inquiryCqiRequiredSignalRefs: normalized.inquiryCqiBacklog.cqiRequiredSignalRefs,
    ownerDid: input.improvement?.ownerDid ?? null,
    approverDid: input.improvement?.approverDid ?? null,
    manualNavigationReady: normalized.inquiryCqiBacklog.manualNavigationReady,
    manualNavigationEffectiveUseAcknowledged: normalized.inquiryCqiBacklog.manualNavigationEffectiveUseAcknowledged,
    roleManualCoverageReceiptHash: normalized.inquiryCqiBacklog.roleManualCoverageReceiptHash,
    residualRiskBasisPoints: input.effectivenessCheck?.residualRiskBasisPoints ?? null,
    metadataOnly: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, cycleHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: cycleHash,
    artifactType: 'continuous_quality_improvement',
    artifactVersion: `${input.siteId}@${input.improvement.improvementId}`,
    classification: 'quality_evidence',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.checkedAtHlc,
    sensitivityTags: [
      'policy_15',
      'metadata_only',
      'human_governance',
      'continuous_quality_improvement',
      'inquiry_cqi_backlog',
      'manual_navigation_readiness',
    ],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateContinuousQualityImprovementCycle(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);

  const policy = evaluatePolicy(input?.cqiPolicy, input?.checkedAtHlc, reasons);
  const improvement = evaluateImprovement(input?.improvement, reasons);
  const sourceFamilies = evaluateSources(input?.sources, policy.requiredSourceFamilies, input?.checkedAtHlc, reasons);
  const { impactDomains, material } = evaluateImpactAssessment(
    input?.impactAssessment,
    policy.requiredImpactDomains,
    input?.checkedAtHlc,
    reasons,
  );
  evaluateImplementationPlan(input?.implementationPlan, input?.improvement, reasons);
  evaluateEffectivenessCheck(input?.effectivenessCheck, input?.implementationPlan, reasons);
  const inquiryCqiBacklog = evaluateInquiryCqiBacklog(input?.inquiryCqiBacklog, input?.implementationPlan, reasons);
  evaluateDecisionForum(input?.decisionForum, input?.improvement, material, reasons);
  evaluateHumanReview(input?.humanReview, input?.improvement, input?.effectivenessCheck, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const normalized = {
    impactDomains,
    improvement,
    inquiryCqiBacklog,
    sourceFamilies,
  };
  const cycleMaterial = buildCycleMaterial(input ?? {}, normalized);
  const cycleHash = sha256Hex(cycleMaterial);
  const cqiCycle = buildCycle(input ?? {}, cycleHash, normalized, material);
  const unique = uniqueReasons(reasons);

  if (unique.length > 0) {
    return {
      decision: 'hold_for_cqi_gap',
      failClosed: true,
      reasons: unique,
      cqiCycle,
      receipt: null,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    cqiCycle,
    receipt: buildReceipt(input, cycleHash),
  };
}
