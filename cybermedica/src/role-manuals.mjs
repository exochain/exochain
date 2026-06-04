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
const ROLE_MANUALS_SCHEMA = 'cybermedica.role_manual_coverage.v1';
const REQUIRED_PERMISSION = 'role_manual_review';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set(['role_manuals_ready', 'hold_for_role_manual_gap']);

const REQUIRED_ROLE_REFS = Object.freeze([
  'ai_quality_reviewer',
  'auditor_inspector',
  'clinical_research_coordinator',
  'cro_portfolio_manager',
  'decision_forum_member',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
  'system_administrator',
  'tenant_administrator',
]);

const REQUIRED_INSTRUCTION_SLOTS = Object.freeze([
  'approval_required',
  'audit_export_result',
  'common_failure_modes',
  'evidence_needed',
  'step_by_step',
  'what_this_is',
  'when_to_use_it',
  'who_owns_it',
]);

const REQUIRED_CROSSLINK_FAMILIES = Object.freeze([
  'acceptance_tests',
  'authority_rules',
  'controls',
  'dashboard_location',
  'decision_forum_escalation',
  'evidence_objects',
  'exochain_receipt_type',
  'open_questions',
  'policies',
  'procedures',
  'tenant_configuration',
  'workflows',
]);

const RAW_ROLE_MANUAL_FIELDS = new Set([
  'body',
  'content',
  'copy',
  'freetext',
  'freetextnote',
  'manualbody',
  'manualcontent',
  'manualcopy',
  'manualtext',
  'rawcontent',
  'rawguidecontent',
  'rawmanual',
  'rawmanualbody',
  'rawmanualcontent',
  'rawmanualtext',
  'rawrolemanual',
  'reviewnotes',
  'rolemanualbody',
  'rolemanualcontent',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_ROLE_MANUAL_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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

function assertNoRawRoleManualContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRoleManualContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ROLE_MANUAL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw role manual content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ROLE_MANUAL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`role manual secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRoleManualContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRoleManualContent(input ?? {});
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

function missingValues(expected, actual) {
  return expected.filter((value) => !actual.includes(value));
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
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
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_actor_cannot_approve_role_manuals');
  addReason(reasons, !input?.authority || input.authority.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
}

function evaluateRoleManualPolicy(policy, reasons) {
  const roleRefs = sortedTextList(policy?.requiredRoleRefs);
  const instructionSlots = sortedTextList(policy?.requiredInstructionSlots);
  const crosslinkFamilies = sortedTextList(policy?.requiredCrosslinkFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'policy_not_active');
  evaluateRequiredSet(roleRefs, REQUIRED_ROLE_REFS, 'policy_role_missing', 'policy_role_unsupported', reasons);
  evaluateRequiredSet(
    instructionSlots,
    REQUIRED_INSTRUCTION_SLOTS,
    'policy_instruction_slot_missing',
    'policy_instruction_slot_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    crosslinkFamilies,
    REQUIRED_CROSSLINK_FAMILIES,
    'policy_crosslink_family_missing',
    'policy_crosslink_family_unsupported',
    reasons,
  );
  addReason(reasons, policy?.manualVersionGovernanceRequired !== true, 'policy_version_governance_absent');
  addReason(reasons, policy?.highRiskClaimsRequireReview !== true, 'policy_high_risk_claim_review_absent');
  addReason(reasons, policy?.aiAssistanceAdvisoryOnly !== true, 'policy_ai_advisory_only_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'policy_evaluation_time_invalid');
}

function evaluateManualCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'cycle_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'cycle_open_time_invalid');
  addReason(reasons, hlcTuple(cycle?.manualReviewAtHlc) === null, 'cycle_manual_review_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanApprovedAtHlc) === null, 'cycle_human_approval_time_invalid');
  addReason(reasons, hlcTuple(cycle?.publishedAtHlc) === null, 'cycle_publication_time_invalid');
  addReason(reasons, hlcTuple(cycle?.receiptRecordedAtHlc) === null, 'cycle_receipt_time_invalid');
  addReason(reasons, hlcBefore(cycle?.manualReviewAtHlc, cycle?.openedAtHlc), 'cycle_manual_review_before_open');
  addReason(reasons, hlcBefore(cycle?.humanApprovedAtHlc, cycle?.manualReviewAtHlc), 'cycle_approval_before_review');
  addReason(reasons, hlcBefore(cycle?.publishedAtHlc, cycle?.humanApprovedAtHlc), 'cycle_publication_before_approval');
  addReason(reasons, hlcBefore(cycle?.receiptRecordedAtHlc, cycle?.publishedAtHlc), 'cycle_receipt_before_publication');
}

function evaluateManualIndex(index, cycle, reasons) {
  addReason(reasons, !isDigest(index?.documentationRunbookReceiptHash), 'manual_index_runbook_receipt_hash_invalid');
  addReason(reasons, !isDigest(index?.contextualManualDrawerReceiptHash), 'manual_index_contextual_drawer_hash_invalid');
  addReason(reasons, !isDigest(index?.documentationPublicationReceiptHash), 'manual_index_publication_hash_invalid');
  addReason(reasons, !isDigest(index?.currentManualSetHash), 'manual_index_current_set_hash_invalid');
  addReason(reasons, !isDigest(index?.versionGovernanceHash), 'manual_index_version_governance_hash_invalid');
  addReason(reasons, index?.metadataOnly !== true, 'manual_index_metadata_boundary_invalid');
  addReason(reasons, index?.protectedContentExcluded !== true, 'manual_index_protected_boundary_invalid');
  addReason(reasons, hlcTuple(index?.reviewedAtHlc) === null, 'manual_index_review_time_invalid');
  addReason(reasons, hlcAfter(index?.reviewedAtHlc, cycle?.receiptRecordedAtHlc), 'manual_index_review_after_receipt');
}

function manualLabel(manual, index) {
  return hasText(manual?.roleRef) ? manual.roleRef : `manual_${index}`;
}

function evaluateRoleManualsCollection(manuals, cycle, reasons) {
  const manualList = Array.isArray(manuals) ? manuals : [];
  const seenRoles = new Set();
  const roleRefs = [];
  const instructionSlots = [];
  const crosslinkFamilies = [];
  const summaries = [];

  addReason(reasons, manualList.length === 0, 'role_manuals_absent');

  manualList.forEach((manual, index) => {
    const label = manualLabel(manual, index);
    const manualInstructionSlots = sortedTextList(manual?.instructionSlots);
    const manualCrosslinkFamilies = sortedTextList(manual?.crosslinkFamilies);
    const roleRef = manual?.roleRef;

    addReason(reasons, !hasText(roleRef), `manual_role_ref_absent:${label}`);
    addReason(reasons, seenRoles.has(roleRef), `manual_role_duplicate:${label}`);
    addReason(reasons, hasText(roleRef) && !REQUIRED_ROLE_REFS.includes(roleRef), `manual_role_unsupported:${label}`);
    if (hasText(roleRef)) {
      seenRoles.add(roleRef);
      roleRefs.push(roleRef);
    }

    addReason(reasons, !hasText(manual?.manualRef), `manual_ref_absent:${label}`);
    addReason(reasons, !hasText(manual?.versionRef), `manual_version_ref_absent:${label}`);
    addReason(reasons, !isDigest(manual?.versionHash), `manual_version_hash_invalid:${label}`);
    evaluateRequiredSet(
      manualInstructionSlots,
      REQUIRED_INSTRUCTION_SLOTS,
      `manual_instruction_slot_missing:${label}`,
      `manual_instruction_slot_unsupported:${label}`,
      reasons,
    );
    evaluateRequiredSet(
      manualCrosslinkFamilies,
      REQUIRED_CROSSLINK_FAMILIES,
      `manual_crosslink_family_missing:${label}`,
      `manual_crosslink_family_unsupported:${label}`,
      reasons,
    );
    addReason(reasons, sortedTextList(manual?.workflowRefs).length === 0, `manual_workflow_refs_absent:${label}`);
    addReason(
      reasons,
      sortedTextList(manual?.evidenceChecklistRefs).length === 0,
      `manual_evidence_checklist_refs_absent:${label}`,
    );
    addReason(reasons, sortedTextList(manual?.dashboardRefs).length === 0, `manual_dashboard_refs_absent:${label}`);
    addReason(
      reasons,
      sortedTextList(manual?.authorityScopeRefs).length === 0,
      `manual_authority_scope_refs_absent:${label}`,
    );
    addReason(
      reasons,
      sortedTextList(manual?.escalationRouteRefs).length === 0,
      `manual_escalation_route_refs_absent:${label}`,
    );
    addReason(
      reasons,
      !sortedTextList(manual?.acceptanceTestRefs).includes('tests/role-manuals.test.mjs'),
      `manual_acceptance_test_ref_missing:${label}`,
    );
    addReason(
      reasons,
      !sortedTextList(manual?.prohibitedClaimFamilies).includes('production_exochain_trust'),
      `manual_prohibited_trust_claim_family_missing:${label}`,
    );
    addReason(reasons, manual?.guidanceNotAuthority !== true, `manual_guidance_authority_boundary_invalid:${label}`);
    addReason(reasons, manual?.approvedForUse !== true, `manual_not_approved_for_use:${label}`);
    addReason(reasons, manual?.reviewedByHuman !== true, `manual_human_review_absent:${label}`);
    addReason(reasons, manual?.metadataOnly !== true, `manual_metadata_boundary_invalid:${label}`);
    addReason(reasons, manual?.protectedContentExcluded !== true, `manual_protected_boundary_invalid:${label}`);
    addReason(reasons, manual?.productionTrustClaim === true, `manual_production_trust_claim_forbidden:${label}`);
    addReason(reasons, hlcTuple(manual?.reviewedAtHlc) === null, `manual_review_time_invalid:${label}`);
    addReason(reasons, hlcTuple(manual?.effectiveAtHlc) === null, `manual_effective_time_invalid:${label}`);
    addReason(reasons, hlcBefore(manual?.reviewedAtHlc, cycle?.manualReviewAtHlc), `manual_review_before_cycle:${label}`);
    addReason(reasons, hlcBefore(manual?.effectiveAtHlc, cycle?.publishedAtHlc), `manual_effective_before_publication:${label}`);

    instructionSlots.push(...manualInstructionSlots);
    crosslinkFamilies.push(...manualCrosslinkFamilies);
    summaries.push({
      roleRef: roleRef ?? null,
      manualRef: manual?.manualRef ?? null,
      versionRef: manual?.versionRef ?? null,
      versionHash: manual?.versionHash ?? null,
    });
  });

  const actualRoleRefs = uniqueSorted(roleRefs);
  evaluateRequiredSet(actualRoleRefs, REQUIRED_ROLE_REFS, 'manual_role_missing', 'manual_role_unsupported', reasons);

  return {
    summaries: summaries.sort((left, right) => String(left.roleRef).localeCompare(String(right.roleRef))),
    roleRefs: actualRoleRefs,
    instructionSlotCoverage: uniqueSorted(instructionSlots),
    crosslinkFamilyCoverage: uniqueSorted(crosslinkFamilies),
  };
}

function evaluateAiAssistance(aiAssistance, cycle, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return false;
  }

  addReason(reasons, !hasText(aiAssistance.assistantRef), 'ai_assistance_ref_absent');
  addReason(reasons, !isDigest(aiAssistance.promptPolicyHash), 'ai_assistance_prompt_policy_hash_invalid');
  addReason(reasons, !isDigest(aiAssistance.outputHash), 'ai_assistance_output_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).some((hash) => !isDigest(hash)), 'ai_assistance_limitation_hash_invalid');
  addReason(reasons, aiAssistance.advisoryOnly !== true, 'ai_assistance_not_advisory');
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, aiAssistance.humanReviewed !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, aiAssistance.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, aiAssistance.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiAssistance.reviewedAtHlc) === null, 'ai_assistance_review_time_invalid');
  addReason(reasons, hlcBefore(aiAssistance.reviewedAtHlc, cycle?.manualReviewAtHlc), 'ai_assistance_review_before_manual_review');
  return true;
}

function evaluateHumanReview(review, cycle, reasons) {
  const reviewerRoles = sortedTextList(review?.reviewerRoleRefs);
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, reviewerRoles.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanApprovedAtHlc), 'human_review_before_cycle_approval');
}

function createManualSetHash(input, collectionSummary) {
  return sha256Hex({
    cycleRef: input?.manualCycle?.cycleRef ?? null,
    crosslinkFamilyCoverage: collectionSummary.crosslinkFamilyCoverage,
    instructionSlotCoverage: collectionSummary.instructionSlotCoverage,
    manualIndexHash: input?.manualIndex?.currentManualSetHash ?? null,
    roleRefs: collectionSummary.roleRefs,
    versionHashes: collectionSummary.summaries.map((manual) => manual.versionHash).filter(hasText),
  });
}

function createRoleManualCoverage(input, finalReasons, collectionSummary, aiAssistanceUsed) {
  const manualSetHash = createManualSetHash(input, collectionSummary);

  return {
    schema: ROLE_MANUALS_SCHEMA,
    ready: finalReasons.length === 0,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    manualSetHash,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.manualCycle?.cycleRef ?? null,
    manualCount: collectionSummary.summaries.length,
    roleRefs: collectionSummary.roleRefs,
    missingRoleRefs: missingValues(REQUIRED_ROLE_REFS, collectionSummary.roleRefs),
    instructionSlotCoverage: collectionSummary.instructionSlotCoverage,
    missingInstructionSlots: missingValues(REQUIRED_INSTRUCTION_SLOTS, collectionSummary.instructionSlotCoverage),
    crosslinkFamilyCoverage: collectionSummary.crosslinkFamilyCoverage,
    missingCrosslinkFamilies: missingValues(REQUIRED_CROSSLINK_FAMILIES, collectionSummary.crosslinkFamilyCoverage),
    manualSummaries: collectionSummary.summaries,
    aiAssistanceUsed,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    receiptRecordedAtHlc: input?.manualCycle?.receiptRecordedAtHlc ?? null,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#documentation-layer',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function buildReceipt(input, roleManuals) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: roleManuals.manualSetHash,
    artifactType: 'role_manual_coverage',
    artifactVersion: input.manualCycle.cycleRef,
    classification: 'metadata_only_role_manuals',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.manualCycle.receiptRecordedAtHlc,
    sensitivityTags: ['documentation_metadata', 'role_manual_coverage', 'no_raw_content'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateRoleManuals(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateRoleManualPolicy(input?.roleManualPolicy, reasons);
  evaluateManualCycle(input?.manualCycle, reasons);
  evaluateManualIndex(input?.manualIndex, input?.manualCycle, reasons);
  const collectionSummary = evaluateRoleManualsCollection(input?.roleManuals, input?.manualCycle, reasons);
  const aiAssistanceUsed = evaluateAiAssistance(input?.aiAssistance, input?.manualCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.manualCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  const roleManuals = createRoleManualCoverage(input, finalReasons, collectionSummary, aiAssistanceUsed);

  if (finalReasons.length > 0) {
    return {
      schema: ROLE_MANUALS_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      roleManuals,
      receipt: null,
    };
  }

  return {
    schema: ROLE_MANUALS_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    roleManuals,
    receipt: buildReceipt(input, roleManuals),
  };
}
