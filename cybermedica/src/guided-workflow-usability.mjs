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
const GUIDED_WORKFLOW_USABILITY_SCHEMA = 'cybermedica.guided_workflow_usability.v1';
const GUIDED_WORKFLOW_USABILITY_RECORD_SCHEMA = 'cybermedica.guided_workflow_usability_record.v1';
const MAX_BASIS_POINTS = 10000;
const MIN_CONTRAST_BASIS_POINTS = 4500;

const REQUIRED_ROLES = Object.freeze([
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
]);

const REQUIRED_WORKFLOWS = Object.freeze([
  'audit_assessment_response',
  'decision_forum_review',
  'deviation_capa_closure',
  'evidence_intake_review',
  'participant_consent_reconsent',
  'safety_event_reporting',
  'sponsor_diligence_export',
  'trial_startup_launch',
]);

const REQUIRED_INDICATORS = Object.freeze([
  'blocked',
  'complete',
  'due_soon',
  'escalated',
  'in_progress',
  'not_started',
  'overdue',
  'pending_human_review',
]);

const REQUIRED_CHECKLISTS = Object.freeze([
  'approval_gates',
  'completeness',
  'freshness',
  'missing_evidence',
  'owner_assignment',
  'privacy_boundary',
  'receipt_readiness',
  'required_evidence',
]);

const RAW_USABILITY_FIELDS = new Set([
  'accessibilitybody',
  'bodycopy',
  'checklistbody',
  'checklistcopy',
  'checklisttext',
  'explanationbody',
  'explanationcopy',
  'explanationtext',
  'freeformusabilitynote',
  'guidebody',
  'guidecopy',
  'guidetext',
  'plainlanguagecopy',
  'plainlanguagetext',
  'rawaccessibilitypayload',
  'rawchecklist',
  'rawexplanation',
  'rawguide',
  'rawpayload',
  'rawstatuslabel',
  'rawusabilitycopy',
  'rawworkflowcopy',
  'statusbody',
  'statuscopy',
  'statuslabel',
  'workflowbody',
  'workflowcopy',
  'workflowtext',
]);

const SECRET_USABILITY_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_BASIS_POINTS;
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

function assertNoRawUsabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawUsabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_USABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw usability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_USABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`usability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawUsabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawUsabilityContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function uniqueReasons(reasons) {
  return uniqueSorted(reasons);
}

function sortByField(fieldName) {
  return (left, right) => String(left[fieldName]).localeCompare(String(right[fieldName]));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function includesAll(required, present) {
  const presentSet = new Set(present);
  return required.every((value) => presentSet.has(value));
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10000n) / BigInt(denominator));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_usability_governor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'usability_govern') && !hasAuthorityPermission(input?.authority, 'govern'),
    'usability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizeUsabilityPlan(input, reasons) {
  const plan = input?.usabilityPlan;
  addReason(reasons, !hasText(plan?.planRef), 'usability_plan_ref_absent');
  addReason(reasons, !hasText(plan?.planVersion), 'usability_plan_version_absent');
  addReason(reasons, plan?.schemaVersion !== GUIDED_WORKFLOW_USABILITY_SCHEMA, 'usability_plan_schema_invalid');
  addReason(reasons, plan?.status !== 'approved', 'usability_plan_not_approved');
  addReason(reasons, !hasText(plan?.roleDashboardRef), 'role_dashboard_ref_absent');
  addReason(reasons, !hasText(plan?.tenantConfigurationRef), 'tenant_configuration_ref_absent');
  addReason(reasons, !isDigest(plan?.accessibilityPolicyHash), 'accessibility_policy_hash_invalid');
  addReason(reasons, !isDigest(plan?.contentStyleGuideHash), 'content_style_guide_hash_invalid');
  addReason(reasons, !isDigest(plan?.statusTaxonomyHash), 'status_taxonomy_hash_invalid');
  addReason(reasons, !isDigest(plan?.checklistModelHash), 'checklist_model_hash_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, plan?.metadataOnly !== true, 'usability_plan_metadata_boundary_invalid');

  return {
    accessibilityPolicyHash: plan?.accessibilityPolicyHash ?? null,
    checklistModelHash: plan?.checklistModelHash ?? null,
    contentStyleGuideHash: plan?.contentStyleGuideHash ?? null,
    planRef: hasText(plan?.planRef) ? plan.planRef : 'USABILITY-PLAN-UNKNOWN',
    planVersion: hasText(plan?.planVersion) ? plan.planVersion : 'VERSION-UNKNOWN',
    roleDashboardRef: plan?.roleDashboardRef ?? null,
    schemaVersion: plan?.schemaVersion ?? null,
    status: plan?.status ?? null,
    statusTaxonomyHash: plan?.statusTaxonomyHash ?? null,
    tenantConfigurationRef: plan?.tenantConfigurationRef ?? null,
  };
}

function normalizeGovernanceReview(input, reasons) {
  const review = input?.governanceReview;
  addReason(reasons, review?.status !== 'approved', 'governance_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'governance_reviewer_absent');
  addReason(reasons, hlcTuple(review?.approvedAtHlc) === null, 'governance_approval_time_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'governance_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, review?.approvedAtHlc), 'governance_review_before_approval');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'governance_review_evidence_hash_invalid');
  addReason(reasons, review?.quorumVerified !== true, 'governance_quorum_unverified');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'governance_ai_final_authority_not_rejected');

  return {
    aiFinalAuthorityRejected: review?.aiFinalAuthorityRejected === true,
    approvedAtHlc: review?.approvedAtHlc ?? null,
    quorumVerified: review?.quorumVerified === true,
    reviewEvidenceHash: review?.reviewEvidenceHash ?? null,
    reviewedAtHlc: review?.reviewedAtHlc ?? null,
    reviewerDid: review?.reviewerDid ?? null,
    status: review?.status ?? null,
  };
}

function normalizeRoleViews(input, reasons) {
  const roleViews = Array.isArray(input?.roleViews) ? [...input.roleViews].sort(sortByField('roleRef')) : [];
  const presentRoles = uniqueSorted(roleViews.map((role) => role?.roleRef).filter(hasText));
  addReason(reasons, roleViews.length === 0, 'role_views_absent');
  for (const required of REQUIRED_ROLES) {
    addReason(reasons, !presentRoles.includes(required), `required_role_view_missing:${required}`);
  }

  return roleViews.map((role) => {
    const roleRef = hasText(role?.roleRef) ? role.roleRef : 'role_unknown';
    const guidedWorkflowRefs = sortedTextList(role?.guidedWorkflowRefs);
    const statusIndicatorRefs = sortedTextList(role?.statusIndicatorRefs);
    const checklistRefs = sortedTextList(role?.checklistRefs);

    addReason(reasons, !REQUIRED_ROLES.includes(roleRef), `role_ref_invalid:${roleRef}`);
    addReason(reasons, !hasText(role?.dashboardRef), `dashboard_ref_absent:${roleRef}`);
    addReason(reasons, guidedWorkflowRefs.length === 0, `role_guided_workflows_absent:${roleRef}`);
    addReason(reasons, statusIndicatorRefs.length === 0, `role_status_indicators_absent:${roleRef}`);
    addReason(reasons, checklistRefs.length === 0, `role_checklists_absent:${roleRef}`);
    addReason(reasons, !isDigest(role?.plainLanguageExplanationHash), `plain_language_explanation_hash_invalid:${roleRef}`);
    addReason(reasons, !isDigest(role?.accessibilityEvidenceHash), `role_accessibility_evidence_hash_invalid:${roleRef}`);
    addReason(reasons, role?.canEscalateToHuman !== true, `role_human_escalation_missing:${roleRef}`);
    addReason(reasons, role?.productionTrustClaim === true, `role_production_trust_claim_forbidden:${roleRef}`);
    addReason(reasons, role?.metadataOnly !== true, `role_view_metadata_boundary_invalid:${roleRef}`);

    return {
      accessibilityEvidenceHash: role?.accessibilityEvidenceHash ?? null,
      canEscalateToHuman: role?.canEscalateToHuman === true,
      checklistRefs,
      dashboardRef: role?.dashboardRef ?? null,
      guidedWorkflowRefs,
      plainLanguageExplanationHash: role?.plainLanguageExplanationHash ?? null,
      roleRef,
      statusIndicatorRefs,
    };
  });
}

function normalizeWorkflowGuides(input, reasons) {
  const guides = Array.isArray(input?.workflowGuides) ? [...input.workflowGuides].sort(sortByField('workflowType')) : [];
  const presentWorkflows = uniqueSorted(guides.map((guide) => guide?.workflowType).filter(hasText));
  addReason(reasons, guides.length === 0, 'workflow_guides_absent');
  for (const required of REQUIRED_WORKFLOWS) {
    addReason(reasons, !presentWorkflows.includes(required), `required_workflow_guide_missing:${required}`);
  }

  return guides.map((guide) => {
    const workflowType = hasText(guide?.workflowType) ? guide.workflowType : 'workflow_unknown';
    const stepRefs = sortedTextList(guide?.stepRefs);
    const gateRefs = sortedTextList(guide?.gateRefs);
    const ownerRoleRefs = sortedTextList(guide?.ownerRoleRefs);

    addReason(reasons, !REQUIRED_WORKFLOWS.includes(workflowType), `workflow_type_invalid:${workflowType}`);
    addReason(reasons, !hasText(guide?.guideRef), `guide_ref_absent:${workflowType}`);
    addReason(reasons, stepRefs.length === 0, `workflow_steps_absent:${workflowType}`);
    addReason(reasons, gateRefs.length === 0, `workflow_gates_absent:${workflowType}`);
    addReason(reasons, ownerRoleRefs.length === 0, `workflow_owner_roles_absent:${workflowType}`);
    addReason(reasons, !hasText(guide?.evidenceChecklistRef), `workflow_evidence_checklist_ref_absent:${workflowType}`);
    addReason(reasons, !hasText(guide?.statusModelRef), `workflow_status_model_ref_absent:${workflowType}`);
    addReason(reasons, !hasText(guide?.fallbackRouteRef), `workflow_fallback_route_absent:${workflowType}`);
    addReason(reasons, !hasText(guide?.humanEscalationRef), `workflow_human_escalation_absent:${workflowType}`);
    addReason(reasons, !isDigest(guide?.guideEvidenceHash), `workflow_guide_evidence_hash_invalid:${workflowType}`);
    addReason(reasons, guide?.metadataOnly !== true, `workflow_guide_metadata_boundary_invalid:${workflowType}`);

    return {
      evidenceChecklistRef: guide?.evidenceChecklistRef ?? null,
      fallbackRouteRef: guide?.fallbackRouteRef ?? null,
      gateRefs,
      guideEvidenceHash: guide?.guideEvidenceHash ?? null,
      guideRef: guide?.guideRef ?? null,
      humanEscalationRef: guide?.humanEscalationRef ?? null,
      ownerRoleRefs,
      statusModelRef: guide?.statusModelRef ?? null,
      stepRefs,
      workflowType,
    };
  });
}

function normalizeStatusIndicators(input, reasons) {
  const indicators = Array.isArray(input?.statusIndicators) ? [...input.statusIndicators].sort(sortByField('indicatorFamily')) : [];
  const presentIndicators = uniqueSorted(indicators.map((indicator) => indicator?.indicatorFamily).filter(hasText));
  addReason(reasons, indicators.length === 0, 'status_indicators_absent');
  for (const required of REQUIRED_INDICATORS) {
    addReason(reasons, !presentIndicators.includes(required), `required_status_indicator_missing:${required}`);
  }

  return indicators.map((indicator) => {
    const indicatorFamily = hasText(indicator?.indicatorFamily) ? indicator.indicatorFamily : 'indicator_unknown';
    const mappedWorkflowTypes = sortedTextList(indicator?.mappedWorkflowTypes);

    addReason(reasons, !REQUIRED_INDICATORS.includes(indicatorFamily), `status_indicator_family_invalid:${indicatorFamily}`);
    addReason(reasons, !hasText(indicator?.indicatorRef), `status_indicator_ref_absent:${indicatorFamily}`);
    addReason(reasons, !isDigest(indicator?.visibleLabelHash), `status_visible_label_hash_invalid:${indicatorFamily}`);
    addReason(reasons, !isDigest(indicator?.accessibleNameHash), `status_accessible_name_hash_invalid:${indicatorFamily}`);
    addReason(reasons, indicator?.colorIndependent !== true, `status_color_independence_missing:${indicatorFamily}`);
    addReason(reasons, indicator?.iconOrShapeCue !== true, `status_icon_shape_cue_missing:${indicatorFamily}`);
    addReason(reasons, mappedWorkflowTypes.length === 0, `status_workflow_mapping_absent:${indicatorFamily}`);
    addReason(
      reasons,
      mappedWorkflowTypes.some((workflowType) => !REQUIRED_WORKFLOWS.includes(workflowType)),
      `status_workflow_mapping_invalid:${indicatorFamily}`,
    );
    addReason(reasons, indicator?.metadataOnly !== true, `status_indicator_metadata_boundary_invalid:${indicatorFamily}`);

    return {
      accessibleNameHash: indicator?.accessibleNameHash ?? null,
      colorIndependent: indicator?.colorIndependent === true,
      iconOrShapeCue: indicator?.iconOrShapeCue === true,
      indicatorFamily,
      indicatorRef: indicator?.indicatorRef ?? null,
      mappedWorkflowTypes,
      visibleLabelHash: indicator?.visibleLabelHash ?? null,
    };
  });
}

function normalizeEvidenceChecklists(input, reasons) {
  const checklists = Array.isArray(input?.evidenceChecklists) ? [...input.evidenceChecklists].sort(sortByField('checklistFamily')) : [];
  const presentChecklists = uniqueSorted(checklists.map((checklist) => checklist?.checklistFamily).filter(hasText));
  addReason(reasons, checklists.length === 0, 'evidence_checklists_absent');
  for (const required of REQUIRED_CHECKLISTS) {
    addReason(reasons, !presentChecklists.includes(required), `required_evidence_checklist_missing:${required}`);
  }

  return checklists.map((checklist) => {
    const checklistFamily = hasText(checklist?.checklistFamily) ? checklist.checklistFamily : 'checklist_unknown';
    const requiredEvidenceRefs = sortedTextList(checklist?.requiredEvidenceRefs);

    addReason(reasons, !REQUIRED_CHECKLISTS.includes(checklistFamily), `evidence_checklist_family_invalid:${checklistFamily}`);
    addReason(reasons, !hasText(checklist?.checklistRef), `evidence_checklist_ref_absent:${checklistFamily}`);
    addReason(reasons, requiredEvidenceRefs.length === 0, `required_evidence_refs_absent:${checklistFamily}`);
    addReason(reasons, checklist?.missingEvidenceVisible !== true, `missing_evidence_visibility_absent:${checklistFamily}`);
    addReason(reasons, !hasText(checklist?.freshnessPolicyRef), `freshness_policy_ref_absent:${checklistFamily}`);
    addReason(reasons, !isBasisPoints(checklist?.completionBasisPoints), `checklist_completion_basis_points_invalid:${checklistFamily}`);
    addReason(reasons, checklist?.completionBasisPoints !== MAX_BASIS_POINTS, `checklist_incomplete:${checklistFamily}`);
    addReason(reasons, !hasText(checklist?.ownerRoleRef), `checklist_owner_role_absent:${checklistFamily}`);
    addReason(reasons, !isDigest(checklist?.checklistEvidenceHash), `checklist_evidence_hash_invalid:${checklistFamily}`);
    addReason(reasons, checklist?.metadataOnly !== true, `evidence_checklist_metadata_boundary_invalid:${checklistFamily}`);

    return {
      checklistEvidenceHash: checklist?.checklistEvidenceHash ?? null,
      checklistFamily,
      checklistRef: checklist?.checklistRef ?? null,
      completionBasisPoints: checklist?.completionBasisPoints ?? null,
      freshnessPolicyRef: checklist?.freshnessPolicyRef ?? null,
      missingEvidenceVisible: checklist?.missingEvidenceVisible === true,
      ownerRoleRef: checklist?.ownerRoleRef ?? null,
      requiredEvidenceRefs,
    };
  });
}

function normalizeExplanationSet(input, governanceReview, reasons) {
  const explanation = input?.explanationSet;
  const audienceRoles = sortedTextList(explanation?.audienceRoles);
  const plainLanguageSummaryHashes = sortedTextList(explanation?.plainLanguageSummaryHashes);

  for (const required of REQUIRED_ROLES) {
    addReason(reasons, !audienceRoles.includes(required), `plain_language_audience_missing:${required}`);
  }
  addReason(reasons, plainLanguageSummaryHashes.length === 0, 'plain_language_summary_hashes_absent');
  addReason(reasons, plainLanguageSummaryHashes.some((hash) => !isDigest(hash)), 'plain_language_summary_hash_invalid');
  addReason(reasons, !isDigest(explanation?.jargonGlossaryHash), 'jargon_glossary_hash_invalid');
  addReason(reasons, explanation?.aiFinalAuthority === true, 'plain_language_ai_final_authority_forbidden');
  addReason(reasons, explanation?.humanApproved !== true, 'plain_language_human_approval_missing');
  addReason(reasons, hlcTuple(explanation?.reviewedAtHlc) === null, 'plain_language_review_time_invalid');
  addReason(
    reasons,
    hlcTuple(explanation?.reviewedAtHlc) !== null &&
      hlcTuple(governanceReview.reviewedAtHlc) !== null &&
      hlcBefore(explanation.reviewedAtHlc, governanceReview.reviewedAtHlc),
    'plain_language_review_before_governance_review',
  );
  addReason(reasons, explanation?.metadataOnly !== true, 'plain_language_metadata_boundary_invalid');

  return {
    aiFinalAuthority: explanation?.aiFinalAuthority === true,
    aiGenerated: explanation?.aiGenerated === true,
    audienceRoles,
    humanApproved: explanation?.humanApproved === true,
    jargonGlossaryHash: explanation?.jargonGlossaryHash ?? null,
    plainLanguageSummaryHashes,
    reviewedAtHlc: explanation?.reviewedAtHlc ?? null,
  };
}

function normalizeAccessibilityReview(input, governanceReview, reasons) {
  const review = input?.accessibilityReview;
  addReason(reasons, review?.standard !== 'wcag_2_2_aa', 'accessibility_standard_invalid');
  addReason(reasons, !isDigest(review?.evidenceHash), 'accessibility_evidence_hash_invalid');
  addReason(reasons, review?.keyboardNavigationVerified !== true, 'accessibility_keyboard_navigation_missing');
  addReason(reasons, review?.screenReaderLabelsVerified !== true, 'accessibility_screen_reader_labels_missing');
  addReason(reasons, review?.colorIndependentStatusVerified !== true, 'accessibility_color_independence_missing');
  addReason(reasons, review?.focusOrderVerified !== true, 'accessibility_focus_order_missing');
  addReason(reasons, review?.reducedMotionSupported !== true, 'accessibility_reduced_motion_missing');
  addReason(reasons, !isBasisPoints(review?.contrastMinimumBasisPoints), 'accessibility_contrast_basis_points_invalid');
  addReason(
    reasons,
    isBasisPoints(review?.contrastMinimumBasisPoints) && review.contrastMinimumBasisPoints < MIN_CONTRAST_BASIS_POINTS,
    'accessibility_contrast_below_minimum',
  );
  addReason(reasons, review?.plainLanguageVerified !== true, 'accessibility_plain_language_missing');
  addReason(reasons, review?.humanReviewed !== true, 'accessibility_human_review_missing');
  addReason(reasons, hlcTuple(review?.testedAtHlc) === null, 'accessibility_test_time_invalid');
  addReason(
    reasons,
    hlcTuple(review?.testedAtHlc) !== null &&
      hlcTuple(governanceReview.reviewedAtHlc) !== null &&
      hlcBefore(review.testedAtHlc, governanceReview.reviewedAtHlc),
    'accessibility_test_before_governance_review',
  );
  addReason(reasons, review?.metadataOnly !== true, 'accessibility_metadata_boundary_invalid');

  return {
    colorIndependentStatusVerified: review?.colorIndependentStatusVerified === true,
    contrastMinimumBasisPoints: review?.contrastMinimumBasisPoints ?? null,
    evidenceHash: review?.evidenceHash ?? null,
    focusOrderVerified: review?.focusOrderVerified === true,
    humanReviewed: review?.humanReviewed === true,
    keyboardNavigationVerified: review?.keyboardNavigationVerified === true,
    plainLanguageVerified: review?.plainLanguageVerified === true,
    reducedMotionSupported: review?.reducedMotionSupported === true,
    screenReaderLabelsVerified: review?.screenReaderLabelsVerified === true,
    standard: review?.standard ?? null,
    testedAtHlc: review?.testedAtHlc ?? null,
  };
}

function normalizeAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined || ai?.used !== true) {
    return {
      confidenceBasisPoints: null,
      evidenceRefs: [],
      finalAuthority: false,
      limitationHashes: [],
      reasoningSummaryHash: null,
      recommendedHumanReviewerDids: [],
      unresolvedAssumptionHashes: [],
      used: false,
    };
  }

  const evidenceRefs = sortedTextList(ai.evidenceRefs);
  const limitationHashes = sortedTextList(ai.limitationHashes);
  const unresolvedAssumptionHashes = sortedTextList(ai.unresolvedAssumptionHashes);
  const recommendedHumanReviewerDids = sortedTextList(ai.recommendedHumanReviewerDids);
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, evidenceRefs.length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !isDigest(ai.reasoningSummaryHash), 'ai_reasoning_summary_hash_invalid');
  addReason(reasons, !isBasisPoints(ai.confidenceBasisPoints), 'ai_confidence_basis_points_invalid');
  addReason(reasons, limitationHashes.some((hash) => !isDigest(hash)), 'ai_limitation_hash_invalid');
  addReason(reasons, unresolvedAssumptionHashes.some((hash) => !isDigest(hash)), 'ai_assumption_hash_invalid');
  addReason(reasons, recommendedHumanReviewerDids.length === 0, 'ai_human_reviewers_absent');

  return {
    confidenceBasisPoints: ai.confidenceBasisPoints ?? null,
    evidenceRefs,
    finalAuthority: ai.finalAuthority === true,
    limitationHashes,
    reasoningSummaryHash: ai.reasoningSummaryHash ?? null,
    recommendedHumanReviewerDids,
    unresolvedAssumptionHashes,
    used: true,
  };
}

function explanationCoverageBasisPoints(explanationSet) {
  return basisPoints(explanationSet.audienceRoles.length, REQUIRED_ROLES.length);
}

function usabilityMaterial(input, sections) {
  const roleCoverage = uniqueSorted(sections.roleViews.map((role) => role.roleRef));
  const workflowCoverage = uniqueSorted(sections.workflowGuides.map((workflow) => workflow.workflowType));
  const indicatorCoverage = uniqueSorted(sections.statusIndicators.map((indicator) => indicator.indicatorFamily));
  const checklistCoverage = uniqueSorted(sections.evidenceChecklists.map((checklist) => checklist.checklistFamily));
  const coverageComplete =
    includesAll(REQUIRED_ROLES, roleCoverage) &&
    includesAll(REQUIRED_WORKFLOWS, workflowCoverage) &&
    includesAll(REQUIRED_INDICATORS, indicatorCoverage) &&
    includesAll(REQUIRED_CHECKLISTS, checklistCoverage);
  const explanationCoverage = explanationCoverageBasisPoints(sections.explanationSet);

  return {
    accessibilityProfile: {
      colorIndependentStatusVerified: sections.accessibilityReview.colorIndependentStatusVerified,
      contrastMinimumBasisPoints: sections.accessibilityReview.contrastMinimumBasisPoints,
      focusOrderVerified: sections.accessibilityReview.focusOrderVerified,
      keyboardNavigationVerified: sections.accessibilityReview.keyboardNavigationVerified,
      plainLanguageVerified: sections.accessibilityReview.plainLanguageVerified,
      reducedMotionSupported: sections.accessibilityReview.reducedMotionSupported,
      screenReaderLabelsVerified: sections.accessibilityReview.screenReaderLabelsVerified,
      standard: sections.accessibilityReview.standard,
    },
    aiAssistance: sections.aiAssistance,
    checklistCoverage,
    evidenceChecklistRefs: sections.evidenceChecklists.map((checklist) => checklist.checklistRef),
    exochainProductionClaim: false,
    explanationCoverageBasisPoints: explanationCoverage,
    explanationSet: sections.explanationSet,
    governanceReview: sections.governanceReview,
    indicatorCoverage,
    planRef: sections.usabilityPlan.planRef,
    planVersion: sections.usabilityPlan.planVersion,
    roleCoverage,
    roleViewRefs: sections.roleViews.map((role) => role.dashboardRef),
    schema: GUIDED_WORKFLOW_USABILITY_RECORD_SCHEMA,
    sourceEvidence: [
      'cyber_medica_qms_prd_master.md:NFR-010',
      'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
    ],
    status: coverageComplete && explanationCoverage === MAX_BASIS_POINTS ? 'approved' : 'incomplete',
    trustState: 'inactive',
    usabilityPlan: sections.usabilityPlan,
    workflowCoverage,
    workflowGuideRefs: sections.workflowGuides.map((workflow) => workflow.guideRef),
  };
}

function attachHash(material) {
  const usabilityHash = sha256Hex(material);
  return {
    ...material,
    usabilityHash,
  };
}

function createUsabilityReceipt(input, usabilityRecord) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: usabilityRecord.usabilityHash,
    artifactType: 'guided_workflow_usability',
    artifactVersion: usabilityRecord.planVersion,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: usabilityRecord.governanceReview.reviewedAtHlc,
    sensitivityTags: ['access_controlled', 'metadata_only', 'operational_qms'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateGuidedWorkflowUsability(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);

  const usabilityPlan = normalizeUsabilityPlan(input, reasons);
  const governanceReview = normalizeGovernanceReview(input, reasons);
  const roleViews = normalizeRoleViews(input, reasons);
  const workflowGuides = normalizeWorkflowGuides(input, reasons);
  const statusIndicators = normalizeStatusIndicators(input, reasons);
  const evidenceChecklists = normalizeEvidenceChecklists(input, reasons);
  const explanationSet = normalizeExplanationSet(input, governanceReview, reasons);
  const accessibilityReview = normalizeAccessibilityReview(input, governanceReview, reasons);
  const aiAssistance = normalizeAiAssistance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: 'cybermedica.guided_workflow_usability_decision.v1',
      permitted: false,
      failClosed: true,
      reasons: unique,
      usabilityRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const material = usabilityMaterial(input, {
    accessibilityReview,
    aiAssistance,
    evidenceChecklists,
    explanationSet,
    governanceReview,
    roleViews,
    statusIndicators,
    usabilityPlan,
    workflowGuides,
  });
  const usabilityRecord = attachHash(material);
  const receipt = createUsabilityReceipt(input, usabilityRecord);

  return {
    schema: 'cybermedica.guided_workflow_usability_decision.v1',
    permitted: true,
    failClosed: false,
    reasons: [],
    usabilityRecord,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
