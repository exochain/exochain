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
const WORKBENCH_SCHEMA = 'cybermedica.ai_quality_review_workbench.v1';
const REQUIRED_PERMISSION = 'ai_quality_workbench_review';

const REQUIRED_AI_REVIEW_FUNCTIONS = Object.freeze([
  'clause_to_evidence_mapping',
  'evidence_completeness_analysis',
  'evidence_freshness_analysis',
  'evidence_contradiction_detection',
  'policy_procedure_gap_detection',
  'protocol_to_site_fit_analysis',
  'consent_readability_analysis',
  'consent_required_element_analysis',
  'vulnerable_population_safeguard_review',
  'recruitment_ethics_review',
  'risk_assessment_adequacy_review',
  'sae_ae_procedure_completeness_review',
  'deviation_procedure_completeness_review',
  'information_management_plan_review',
  'alcoac_support_review',
  'training_gap_detection',
  'delegation_mismatch_detection',
  'qualification_mismatch_detection',
  'facility_equipment_readiness_review',
  'clinical_trial_product_control_review',
  'communication_plan_adequacy_review',
  'open_finding_prioritization',
  'capa_root_cause_quality_review',
  'capa_effectiveness_check_suggestions',
  'kpi_trend_anomaly_detection',
  'sponsor_diligence_summary_generation',
  'audit_packet_assembly_recommendations',
  'decision_forum_brief_generation',
  'escalation_recommendations',
  'human_review_prompt_generation',
]);

const REQUIRED_FUNCTION_SET = new Set(REQUIRED_AI_REVIEW_FUNCTIONS);
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ITEM_PRIORITIES = new Set(['critical', 'high', 'standard', 'low']);
const ITEM_STATUSES = new Set(['human_reviewed', 'needs_human_review', 'queued_for_review']);
const HUMAN_REVIEW_DECISIONS = new Set(['hold_for_workbench_gap', 'workbench_ready_inactive_trust']);

const RAW_WORKBENCH_FIELDS = new Set([
  'aifreeformoutput',
  'aioutput',
  'analysisbody',
  'freeform',
  'freetext',
  'freetextnote',
  'prompttext',
  'rawaioutput',
  'rawanalysis',
  'rawcontent',
  'rawfinding',
  'rawprompt',
  'rawrecommendation',
  'rawreview',
  'rawsource',
  'reasoningtext',
  'reviewnotes',
  'sourcecontent',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'workbenchbody',
]);

const SECRET_WORKBENCH_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawWorkbenchContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawWorkbenchContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_WORKBENCH_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw AI quality review workbench field is not allowed at ${path}.${key}`);
    }
    if (SECRET_WORKBENCH_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`AI quality review workbench secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawWorkbenchContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawWorkbenchContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function functionOrder(functionFamily) {
  const index = REQUIRED_AI_REVIEW_FUNCTIONS.indexOf(functionFamily);
  return index === -1 ? REQUIRED_AI_REVIEW_FUNCTIONS.length : index;
}

function reviewItemLabel(item, index = null) {
  if (hasText(item?.itemRef)) {
    return item.itemRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(
    reasons,
    Array.isArray(input?.actor?.roleRefs) && !input.actor.roleRefs.includes('ai_quality_reviewer'),
    'ai_quality_reviewer_role_missing',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'ai_quality_workbench_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateWorkbench(workbench, reasons) {
  addReason(reasons, !hasText(workbench?.workbenchRef), 'workbench_ref_absent');
  addReason(reasons, workbench?.schemaVersion !== WORKBENCH_SCHEMA, 'workbench_schema_invalid');
  addReason(reasons, workbench?.role !== 'ai_quality_reviewer', 'workbench_role_invalid');
  addReason(reasons, hlcTuple(workbench?.generatedAtHlc) === null, 'workbench_time_invalid');
  addReason(reasons, !isDigest(workbench?.sourceIndexHash), 'workbench_source_index_hash_invalid');
  addReason(reasons, !isDigest(workbench?.modelRegistryHash), 'workbench_model_registry_hash_invalid');
  addReason(reasons, !isDigest(workbench?.promptLibraryHash), 'workbench_prompt_library_hash_invalid');
  addReason(reasons, workbench?.metadataOnly !== true, 'workbench_metadata_boundary_invalid');
  addReason(reasons, workbench?.rawPayloadExcluded !== true, 'workbench_raw_payload_boundary_invalid');
  addReason(reasons, workbench?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluatePolicy(policy, reasons) {
  const requiredFunctionFamilies = sortedTextList(policy?.requiredFunctionFamilies);
  const allowedReviewerRoles = sortedTextList(policy?.allowedReviewerRoles);

  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'policy_not_active');
  addReason(reasons, allowedReviewerRoles.length === 0, 'allowed_reviewer_roles_absent');
  addReason(reasons, policy?.assistanceOnly !== true, 'ai_assistance_only_policy_absent');
  addReason(reasons, policy?.allowAiFinalAuthority === true, 'policy_allows_ai_final_authority');
  addReason(reasons, policy?.requiresEvidenceRefs !== true, 'policy_evidence_refs_requirement_absent');
  addReason(reasons, policy?.requiresHumanPrompt !== true, 'policy_human_prompt_requirement_absent');
  addReason(reasons, policy?.requiresConfidenceLimits !== true, 'policy_confidence_limits_requirement_absent');
  addReason(reasons, policy?.contestable !== true, 'policy_contestation_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'policy_time_invalid');

  for (const functionFamily of REQUIRED_AI_REVIEW_FUNCTIONS) {
    addReason(
      reasons,
      !requiredFunctionFamilies.includes(functionFamily),
      `policy_required_function_missing:${functionFamily}`,
    );
  }
  for (const functionFamily of requiredFunctionFamilies) {
    addReason(
      reasons,
      !REQUIRED_FUNCTION_SET.has(functionFamily),
      `policy_required_function_unsupported:${functionFamily}`,
    );
  }

  return allowedReviewerRoles;
}

function normalizeReviewItems(input, allowedReviewerRoles, reasons) {
  const items = Array.isArray(input?.reviewItems) ? [...input.reviewItems] : [];
  addReason(reasons, items.length === 0, 'review_items_absent');

  const normalizedItems = items.map((item, index) => {
    const itemRef = reviewItemLabel(item, index);
    const sourceModuleRefs = sortedTextList(item?.sourceModuleRefs);
    const evidenceRefs = sortedTextList(item?.evidenceRefs);
    const limitationHashes = sortedTextList(item?.limitationHashes);
    const unresolvedAssumptionHashes = sortedTextList(item?.unresolvedAssumptionHashes);
    const conflictRefs = sortedTextList(item?.conflictRefs);
    const functionFamily = hasText(item?.functionFamily) ? item.functionFamily : 'unknown';
    const recommendedHumanReviewerRole = item?.recommendedHumanReviewerRole ?? null;

    addReason(reasons, !hasText(item?.itemRef), 'item_ref_absent');
    addReason(reasons, !REQUIRED_FUNCTION_SET.has(functionFamily), `item_function_unsupported:${itemRef}`);
    addReason(reasons, sourceModuleRefs.length === 0, `item_source_module_refs_absent:${itemRef}`);
    addReason(reasons, evidenceRefs.length === 0, `item_evidence_refs_absent:${itemRef}`);
    addReason(reasons, !isDigest(item?.inputManifestHash), `item_input_manifest_hash_invalid:${itemRef}`);
    addReason(reasons, !isDigest(item?.outputHash), `item_output_hash_invalid:${itemRef}`);
    addReason(reasons, !isDigest(item?.reasoningSummaryHash), `item_reasoning_summary_hash_invalid:${itemRef}`);
    addReason(reasons, limitationHashes.length === 0, `item_limitation_hashes_absent:${itemRef}`);
    for (const limitationHash of limitationHashes) {
      addReason(reasons, !isDigest(limitationHash), `item_limitation_hash_invalid:${itemRef}`);
    }
    for (const assumptionHash of unresolvedAssumptionHashes) {
      addReason(reasons, !isDigest(assumptionHash), `item_unresolved_assumption_hash_invalid:${itemRef}`);
    }
    addReason(reasons, !isBasisPoints(item?.confidenceBasisPoints), `item_confidence_invalid:${itemRef}`);
    addReason(reasons, !ITEM_PRIORITIES.has(item?.priority), `item_priority_invalid:${itemRef}`);
    addReason(reasons, !ITEM_STATUSES.has(item?.status), `item_status_invalid:${itemRef}`);
    addReason(reasons, !hasText(recommendedHumanReviewerRole), `item_reviewer_role_absent:${itemRef}`);
    addReason(
      reasons,
      hasText(recommendedHumanReviewerRole) &&
        allowedReviewerRoles.length > 0 &&
        !allowedReviewerRoles.includes(recommendedHumanReviewerRole),
      `item_reviewer_role_not_allowed:${itemRef}`,
    );
    addReason(reasons, !isDigest(item?.humanPromptHash), `item_human_prompt_hash_invalid:${itemRef}`);
    addReason(reasons, hlcTuple(item?.createdAtHlc) === null, `item_time_invalid:${itemRef}`);
    addReason(reasons, item?.metadataOnly !== true, `item_metadata_boundary_invalid:${itemRef}`);
    addReason(reasons, item?.finalAuthority === true, `item_final_authority_forbidden:${itemRef}`);

    return {
      confidenceBasisPoints: item?.confidenceBasisPoints ?? null,
      conflictRefs,
      createdAtHlc: item?.createdAtHlc ?? null,
      decisionForumCandidate: item?.decisionForumCandidate === true,
      escalationRecommended: item?.escalationRecommended === true,
      evidenceRefs,
      finalAuthority: item?.finalAuthority === true,
      functionFamily,
      humanPromptHash: item?.humanPromptHash ?? null,
      inputManifestHash: item?.inputManifestHash ?? null,
      itemRef,
      limitationHashes,
      metadataOnly: item?.metadataOnly === true,
      outputHash: item?.outputHash ?? null,
      priority: item?.priority ?? null,
      reasoningSummaryHash: item?.reasoningSummaryHash ?? null,
      recommendedHumanReviewerRole,
      sourceModuleRefs,
      status: item?.status ?? null,
      unresolvedAssumptionHashes,
    };
  });

  const coveredFunctions = new Set(normalizedItems.map((item) => item.functionFamily));
  for (const functionFamily of REQUIRED_AI_REVIEW_FUNCTIONS) {
    addReason(reasons, !coveredFunctions.has(functionFamily), `required_function_missing:${functionFamily}`);
  }

  return normalizedItems.sort(
    (left, right) =>
      functionOrder(left.functionFamily) - functionOrder(right.functionFamily) ||
      String(left.itemRef).localeCompare(String(right.itemRef)),
  );
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !hasText(review?.reviewerRole), 'human_review_role_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.workbench?.generatedAtHlc),
    'human_review_time_before_workbench',
  );
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_bundle_hash_invalid');
  addReason(reasons, !hasText(review?.decisionForumEscalationPolicyRef), 'decision_forum_escalation_policy_absent');
  addReason(reasons, sortedTextList(review?.contextRefs).length === 0, 'human_review_context_refs_absent');
  addReason(reasons, review?.activationOnlyBlockersAccepted !== true, 'activation_only_blockers_not_accepted');
}

function summarizeWorkbench(items) {
  const humanReviewQueue = items
    .map((item) => `${item.recommendedHumanReviewerRole}:${item.itemRef}`)
    .sort();
  const escalationQueue = items
    .filter((item) => item.escalationRecommended)
    .map((item) => `${item.itemRef}:${item.functionFamily}`)
    .sort();
  const decisionForumBriefQueue = items
    .filter((item) => item.decisionForumCandidate)
    .map((item) => `${item.itemRef}:${item.functionFamily}`)
    .sort();

  return {
    decisionForumBriefQueue,
    escalationQueue,
    humanReviewQueue,
    summary: {
      criticalPriorityCount: items.filter((item) => item.priority === 'critical').length,
      decisionForumCandidateCount: decisionForumBriefQueue.length,
      escalationRecommendedCount: escalationQueue.length,
      humanPromptCount: items.filter((item) => isDigest(item.humanPromptHash)).length,
      reviewItemCount: items.length,
    },
  };
}

export function evaluateAiQualityReviewWorkbench(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateWorkbench(input?.workbench, reasons);
  const allowedReviewerRoles = evaluatePolicy(input?.aiReviewPolicy, reasons);
  const reviewItems = normalizeReviewItems(input, allowedReviewerRoles, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      canShowProductionTrustClaim: false,
      denialReasons,
      exochainProductionClaim: false,
      receipt: null,
      status: 'denied',
      trustState: 'inactive',
      workbench: null,
    };
  }

  const { decisionForumBriefQueue, escalationQueue, humanReviewQueue, summary } = summarizeWorkbench(reviewItems);
  const workbenchPayload = {
    assistanceOnly: true,
    aiFinalAuthority: false,
    allowedReviewerRoles,
    contextRefs: sortedTextList(input.humanReview.contextRefs),
    decisionForumBriefQueue,
    escalationQueue,
    functionFamiliesCovered: REQUIRED_AI_REVIEW_FUNCTIONS,
    humanReviewDecision: input.humanReview.decision,
    humanReviewQueue,
    policyRef: input.aiReviewPolicy.policyRef,
    requiredFunctionFamilies: REQUIRED_AI_REVIEW_FUNCTIONS,
    reviewItems,
    schema: WORKBENCH_SCHEMA,
    summary,
    tenantId: input.tenantId,
    trustState: 'inactive',
    workbenchRef: input.workbench.workbenchRef,
  };
  const workbenchHash = sha256Hex(workbenchPayload);
  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: workbenchHash,
    artifactType: 'ai_quality_review_workbench',
    artifactVersion: input.aiReviewPolicy.policyRef,
    classification: 'qms_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['ai_review_metadata', 'metadata_only', 'qms'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });

  return {
    canShowProductionTrustClaim: false,
    denialReasons: [],
    exochainProductionClaim: false,
    receipt,
    status: 'ready',
    trustState: 'inactive',
    workbench: {
      ...workbenchPayload,
      exochainProductionClaim: false,
      workbenchHash,
    },
  };
}
