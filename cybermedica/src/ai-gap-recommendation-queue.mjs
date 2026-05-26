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
const QUEUE_SCHEMA = 'cybermedica.ai_gap_recommendation_queue.v1';
const DECISION_SCHEMA = 'cybermedica.ai_gap_recommendation_queue_decision.v1';
const REQUIRED_PERMISSION = 'ai_gap_triage';

const REQUIRED_GAP_FAMILIES = Object.freeze([
  'consent_version_gap',
  'control_gap',
  'data_integrity_gap',
  'documentation_gap',
  'evidence_aging',
  'policy_procedure_gap',
  'protocol_amendment_gap',
  'safety_signal',
  'sponsor_expectation',
  'training_gap',
]);

const REQUIRED_ROUTE_TYPES = Object.freeze([
  'capa',
  'cqi',
  'decision_forum',
  'documentation_update',
  'drift_signal',
  'training_update',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const GAP_FAMILIES = new Set(REQUIRED_GAP_FAMILIES);
const ROUTE_TYPES = new Set(REQUIRED_ROUTE_TYPES);
const RISK_LEVELS = new Set(['critical', 'major', 'minor', 'observation']);
const URGENCY_LEVELS = new Set(['deferred', 'standard', 'urgent']);
const QUEUE_PRIORITIES = new Set(['critical', 'high', 'standard', 'low']);
const HUMAN_REVIEW_DECISIONS = new Set(['ai_gap_queue_ready', 'hold_for_gap_review']);

const RAW_AI_GAP_FIELDS = new Set([
  'aifreeformoutput',
  'aigapnarrative',
  'aioutput',
  'analysisbody',
  'comment',
  'content',
  'evidencenarrative',
  'freeform',
  'freetext',
  'freetextnote',
  'gapdescription',
  'gapnarrative',
  'rawaioutput',
  'rawanalysis',
  'rawcontent',
  'rawgap',
  'rawprompt',
  'rawrecommendation',
  'rawreview',
  'rawsource',
  'rawsourcedata',
  'recommendationbody',
  'recommendationtext',
  'reviewnotes',
  'sourcedocumentbody',
]);

const SECRET_AI_GAP_FIELDS = new Set([
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

function assertNoRawAiGapContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAiGapContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AI_GAP_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw AI gap recommendation field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AI_GAP_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`AI gap recommendation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAiGapContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAiGapContent(input ?? {});
  canonicalize(input ?? {});
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

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function recommendationLabel(recommendation, index = null) {
  if (hasText(recommendation?.recommendationRef)) {
    return recommendation.recommendationRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function queueItemLabel(item, index = null) {
  if (hasText(item?.queueItemRef)) {
    return item.queueItemRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, supportedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !supportedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_gap_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'ai_gap_triage_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateQueuePolicy(policy, reasons) {
  const requiredGapFamilies = sortedTextList(policy?.requiredGapFamilies);
  const allowedRouteTypes = sortedTextList(policy?.allowedRouteTypes);

  addReason(reasons, !hasText(policy?.policyRef), 'queue_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'queue_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'queue_policy_not_active');
  addReason(reasons, policy?.materialDecisionForumRequired !== true, 'material_decision_forum_policy_absent');
  addReason(reasons, policy?.humanReviewRequired !== true, 'human_review_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'queue_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'queue_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'queue_policy_time_invalid');

  evaluateRequiredSet(
    requiredGapFamilies,
    REQUIRED_GAP_FAMILIES,
    'gap_family_policy_missing',
    'gap_family_policy_unsupported',
    GAP_FAMILIES,
    reasons,
  );
  evaluateRequiredSet(
    allowedRouteTypes,
    REQUIRED_ROUTE_TYPES,
    'route_type_policy_missing',
    'route_type_policy_unsupported',
    ROUTE_TYPES,
    reasons,
  );

  return { allowedRouteTypes, requiredGapFamilies };
}

function evaluateQueueCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'queue_cycle_ref_absent');
  addReason(reasons, cycle?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'queue_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'queue_cycle_protected_boundary_invalid');

  const fields = [
    'openedAtHlc',
    'recommendationsCapturedAtHlc',
    'triagedAtHlc',
    'routedAtHlc',
    'humanReviewedAtHlc',
    'auditRecordedAtHlc',
  ];
  for (const field of fields) {
    addReason(reasons, hlcTuple(cycle?.[field]) === null, `queue_cycle_${field}_invalid`);
  }
  addReason(
    reasons,
    hlcBefore(cycle?.recommendationsCapturedAtHlc, cycle?.openedAtHlc),
    'queue_cycle_recommendationsCapturedAtHlc_before_openedAtHlc',
  );
  addReason(
    reasons,
    hlcBefore(cycle?.triagedAtHlc, cycle?.recommendationsCapturedAtHlc),
    'queue_cycle_triagedAtHlc_before_recommendationsCapturedAtHlc',
  );
  addReason(reasons, hlcBefore(cycle?.routedAtHlc, cycle?.triagedAtHlc), 'queue_cycle_routedAtHlc_before_triagedAtHlc');
  addReason(
    reasons,
    hlcBefore(cycle?.humanReviewedAtHlc, cycle?.routedAtHlc),
    'queue_cycle_humanReviewedAtHlc_before_routedAtHlc',
  );
  addReason(
    reasons,
    hlcBefore(cycle?.auditRecordedAtHlc, cycle?.humanReviewedAtHlc),
    'queue_cycle_auditRecordedAtHlc_before_humanReviewedAtHlc',
  );
}

function evaluateAiReviewManifest(manifest, cycle, reasons) {
  addReason(reasons, !hasText(manifest?.manifestRef), 'ai_review_manifest_ref_absent');
  addReason(reasons, !isDigest(manifest?.modelRefHash), 'ai_model_ref_hash_invalid');
  addReason(reasons, !isDigest(manifest?.promptHash), 'ai_prompt_hash_invalid');
  addReason(reasons, !isDigest(manifest?.inputManifestHash), 'ai_input_manifest_hash_invalid');
  addReason(reasons, !isDigest(manifest?.outputManifestHash), 'ai_output_manifest_hash_invalid');
  addReason(reasons, manifest?.noRawPromptOrOutput !== true, 'ai_prompt_output_boundary_absent');
  addReason(reasons, manifest?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(
    reasons,
    manifest?.advisoryOnly !== true || manifest?.finalAuthority === true,
    'ai_review_manifest_advisory_boundary_invalid',
  );
  addReason(reasons, manifest?.metadataOnly !== true, 'ai_review_manifest_metadata_boundary_invalid');
  addReason(reasons, manifest?.protectedContentExcluded !== true, 'ai_review_manifest_protected_boundary_invalid');
  addReason(reasons, hlcTuple(manifest?.reviewedAtHlc) === null, 'ai_review_manifest_time_invalid');
  addReason(
    reasons,
    hlcBefore(manifest?.reviewedAtHlc, cycle?.openedAtHlc),
    'ai_review_manifest_before_queue_open',
  );
}

function recommendationIsMaterial(recommendation) {
  return (
    recommendation?.riskLevel === 'critical' ||
    recommendation?.urgency === 'urgent' ||
    recommendation?.participantSafetyImpact === true ||
    recommendation?.dataIntegrityImpact === true ||
    recommendation?.sponsorCroImpact === true
  );
}

function evaluateRecommendations(recommendations, requiredGapFamilies, cycle, reasons) {
  addReason(reasons, !Array.isArray(recommendations) || recommendations.length === 0, 'recommendations_absent');
  if (!Array.isArray(recommendations)) {
    return {
      gapFamilies: [],
      materialRecommendationRefs: [],
      recommendationRefs: [],
      recommendationSummaries: [],
    };
  }

  const gapFamilies = [];
  const materialRecommendationRefs = [];
  const recommendationRefs = [];
  const recommendationSummaries = [];
  const seenRecommendationRefs = new Set();

  for (const family of requiredGapFamilies) {
    addReason(
      reasons,
      !recommendations.some((recommendation) => recommendation?.gapFamily === family),
      `gap_family_missing:${family}`,
    );
  }

  recommendations.forEach((recommendation, index) => {
    const label = recommendationLabel(recommendation, index);
    const controlRefs = sortedTextList(recommendation?.controlRefs);
    addReason(reasons, !hasText(recommendation?.recommendationRef), `recommendation_ref_absent:${label}`);
    addReason(reasons, seenRecommendationRefs.has(recommendation?.recommendationRef), `recommendation_ref_duplicate:${label}`);
    if (hasText(recommendation?.recommendationRef)) {
      seenRecommendationRefs.add(recommendation.recommendationRef);
      recommendationRefs.push(recommendation.recommendationRef);
    }
    addReason(reasons, !GAP_FAMILIES.has(recommendation?.gapFamily), `gap_family_unsupported:${label}`);
    addReason(reasons, !requiredGapFamilies.includes(recommendation?.gapFamily), `gap_family_not_allowed:${label}`);
    addReason(reasons, !hasText(recommendation?.sourceReviewRef), `recommendation_source_review_absent:${label}`);
    addReason(reasons, !isDigest(recommendation?.sourceEvidenceHash), `recommendation_source_evidence_hash_invalid:${label}`);
    addReason(reasons, controlRefs.length === 0, `recommendation_control_refs_absent:${label}`);
    addReason(reasons, !isBasisPoints(recommendation?.confidenceBasisPoints), `recommendation_confidence_invalid:${label}`);
    addReason(reasons, !RISK_LEVELS.has(recommendation?.riskLevel), `recommendation_risk_level_invalid:${label}`);
    addReason(reasons, !URGENCY_LEVELS.has(recommendation?.urgency), `recommendation_urgency_invalid:${label}`);
    addReason(
      reasons,
      recommendation?.advisoryOnly !== true || recommendation?.finalAuthority === true,
      `recommendation_advisory_boundary_invalid:${label}`,
    );
    addReason(reasons, recommendation?.finalAuthority === true, 'ai_final_authority_forbidden');
    addReason(reasons, recommendation?.reviewable !== true, `recommendation_reviewable_absent:${label}`);
    addReason(reasons, recommendation?.metadataOnly !== true, `recommendation_metadata_boundary_invalid:${label}`);
    addReason(reasons, recommendation?.protectedContentExcluded !== true, `recommendation_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(recommendation?.detectedAtHlc) === null, `recommendation_detected_time_invalid:${label}`);
    addReason(
      reasons,
      hlcBefore(recommendation?.detectedAtHlc, cycle?.openedAtHlc),
      `recommendation_detected_before_queue_open:${label}`,
    );

    if (hasText(recommendation?.gapFamily)) {
      gapFamilies.push(recommendation.gapFamily);
    }
    if (recommendationIsMaterial(recommendation) && hasText(recommendation?.recommendationRef)) {
      materialRecommendationRefs.push(recommendation.recommendationRef);
    }
    recommendationSummaries.push({
      confidenceBasisPoints: recommendation?.confidenceBasisPoints ?? null,
      controlRefs,
      gapFamily: recommendation?.gapFamily ?? null,
      recommendationRef: recommendation?.recommendationRef ?? null,
      riskLevel: recommendation?.riskLevel ?? null,
      urgency: recommendation?.urgency ?? null,
    });
  });

  return {
    gapFamilies: uniqueSorted(gapFamilies),
    materialRecommendationRefs: uniqueSorted(materialRecommendationRefs),
    recommendationRefs: uniqueSorted(recommendationRefs),
    recommendationSummaries: recommendationSummaries.sort((left, right) =>
      String(left.recommendationRef).localeCompare(String(right.recommendationRef)),
    ),
  };
}

function evaluateQueueItems(items, recommendationRefs, allowedRouteTypes, cycle, reasons) {
  addReason(reasons, !Array.isArray(items) || items.length === 0, 'queue_items_absent');
  if (!Array.isArray(items)) {
    return {
      queueItemRefs: [],
      queueItemSummaries: [],
      routeTypes: [],
    };
  }

  const queueItemRefs = [];
  const queueItemSummaries = [];
  const routeTypes = [];
  const queuedRecommendationRefs = new Set();
  const recommendationSet = new Set(recommendationRefs);
  const seenItemRefs = new Set();

  items.forEach((item, index) => {
    const label = queueItemLabel(item, index);
    const reviewRoles = sortedTextList(item?.requiredReviewRoleRefs);
    addReason(reasons, !hasText(item?.queueItemRef), `queue_item_ref_absent:${label}`);
    addReason(reasons, seenItemRefs.has(item?.queueItemRef), `queue_item_ref_duplicate:${label}`);
    if (hasText(item?.queueItemRef)) {
      seenItemRefs.add(item.queueItemRef);
      queueItemRefs.push(item.queueItemRef);
    }
    addReason(reasons, !recommendationSet.has(item?.recommendationRef), `queue_item_recommendation_unknown:${label}`);
    if (hasText(item?.recommendationRef)) {
      queuedRecommendationRefs.add(item.recommendationRef);
    }
    addReason(reasons, !hasText(item?.ownerRoleRef), `queue_item_owner_role_absent:${label}`);
    addReason(reasons, !QUEUE_PRIORITIES.has(item?.priority), `queue_item_priority_invalid:${label}`);
    addReason(reasons, !ROUTE_TYPES.has(item?.routeType), `queue_item_route_type_invalid:${label}`);
    addReason(reasons, !allowedRouteTypes.includes(item?.routeType), `queue_item_route_type_not_allowed:${label}`);
    addReason(reasons, reviewRoles.length === 0, `queue_item_review_roles_absent:${label}`);
    addReason(reasons, !isDigest(item?.evidenceReviewHash), `queue_item_evidence_review_hash_invalid:${label}`);
    addReason(reasons, !isDigest(item?.rationaleHash), `queue_item_rationale_hash_invalid:${label}`);
    addReason(reasons, item?.metadataOnly !== true, `queue_item_metadata_boundary_invalid:${label}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `queue_item_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(item?.triagedAtHlc) === null, `queue_item_triaged_time_invalid:${label}`);
    addReason(reasons, hlcTuple(item?.dueAtHlc) === null, `queue_item_due_time_invalid:${label}`);
    addReason(reasons, hlcBefore(item?.triagedAtHlc, cycle?.triagedAtHlc), `queue_item_triaged_before_cycle:${label}`);
    addReason(reasons, hlcBefore(item?.dueAtHlc, item?.triagedAtHlc), `queue_item_due_before_triage:${label}`);
    if (hasText(item?.routeType)) {
      routeTypes.push(item.routeType);
    }
    queueItemSummaries.push({
      ownerRoleRef: item?.ownerRoleRef ?? null,
      priority: item?.priority ?? null,
      queueItemRef: item?.queueItemRef ?? null,
      recommendationRef: item?.recommendationRef ?? null,
      routeType: item?.routeType ?? null,
    });
  });

  for (const recommendationRef of recommendationRefs) {
    addReason(reasons, !queuedRecommendationRefs.has(recommendationRef), `queue_item_absent:${recommendationRef}`);
  }

  return {
    queueItemRefs: uniqueSorted(queueItemRefs),
    queueItemSummaries: queueItemSummaries.sort((left, right) => String(left.queueItemRef).localeCompare(String(right.queueItemRef))),
    routeTypes: uniqueSorted(routeTypes),
  };
}

function evaluateDownstreamRouting(routing, routeTypes, materialRecommendationRefs, cycle, policy, reasons) {
  addReason(reasons, !hasText(routing?.routingRef), 'routing_ref_absent');
  addReason(reasons, routing?.metadataOnly !== true, 'routing_metadata_boundary_invalid');
  addReason(reasons, routing?.protectedContentExcluded !== true, 'routing_protected_boundary_invalid');
  addReason(reasons, hlcTuple(routing?.routedAtHlc) === null, 'routing_time_invalid');
  addReason(reasons, hlcBefore(routing?.routedAtHlc, cycle?.routedAtHlc), 'routing_before_cycle_routing_step');

  const routedRouteTypes = sortedTextList(routing?.routeTypes);
  for (const routeType of routeTypes) {
    addReason(reasons, !routedRouteTypes.includes(routeType), `route_type_missing:${routeType}`);
  }
  for (const routeType of routedRouteTypes) {
    addReason(reasons, !ROUTE_TYPES.has(routeType), `route_type_unsupported:${routeType}`);
  }

  const requiresDecisionForum = materialRecommendationRefs.length > 0 && policy?.materialDecisionForumRequired === true;
  const decisionForumMatterRefs = sortedTextList(routing?.decisionForumMatterRefs);
  addReason(
    reasons,
    requiresDecisionForum && decisionForumMatterRefs.length === 0,
    'material_decision_forum_absent',
  );
  addReason(reasons, routeTypes.includes('cqi') && !isDigest(routing?.cqiQueueHash), 'cqi_queue_hash_invalid');
  addReason(reasons, routeTypes.includes('capa') && sortedTextList(routing?.capaRefs).length === 0, 'capa_route_refs_absent');
  addReason(
    reasons,
    routeTypes.includes('documentation_update') && sortedTextList(routing?.documentationUpdateRefs).length === 0,
    'documentation_update_route_refs_absent',
  );
  addReason(
    reasons,
    routeTypes.includes('drift_signal') && sortedTextList(routing?.driftSignalRefs).length === 0,
    'drift_signal_route_absent',
  );
  addReason(
    reasons,
    routeTypes.includes('training_update') && sortedTextList(routing?.trainingUpdateRefs).length === 0,
    'training_update_route_refs_absent',
  );

  return {
    decisionForumInvoked: decisionForumMatterRefs.length > 0,
    decisionForumMatterRefs,
    decisionForumRequired: requiresDecisionForum,
  };
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, humanReview, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'ai_gap_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'ai_gap_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'ai_gap_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'ai_gap_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'ai_gap_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'ai_gap_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, humanReview?.reviewedAtHlc), 'ai_gap_audit_before_review');
}

function buildQueue(input, recommendationSummary, queueItemSummary, routingSummary) {
  const queueHash = sha256Hex({
    auditRecordHash: input.auditRecord.auditRecordHash,
    cycleRef: input.queueCycle.cycleRef,
    decisionForumMatterRefs: routingSummary.decisionForumMatterRefs,
    humanDecisionHash: input.humanReview.decisionHash,
    queueItemSummaries: queueItemSummary.queueItemSummaries,
    recommendationSummaries: recommendationSummary.recommendationSummaries,
    tenantId: input.tenantId,
  });

  return {
    schema: QUEUE_SCHEMA,
    queueId: `cmaigap_${sha256Hex({
      queueHash,
      queueRef: input.queueCycle.cycleRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    cycleRef: input.queueCycle.cycleRef,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    aiFinalAuthority: false,
    humanFinalAuthorityRequired: true,
    gapFamilies: recommendationSummary.gapFamilies,
    routeTypes: queueItemSummary.routeTypes,
    recommendationCount: recommendationSummary.recommendationRefs.length,
    queueItemCount: queueItemSummary.queueItemRefs.length,
    materialRecommendationRefs: recommendationSummary.materialRecommendationRefs,
    recommendationRefs: recommendationSummary.recommendationRefs,
    queueItemRefs: queueItemSummary.queueItemRefs,
    decisionForumRequired: routingSummary.decisionForumRequired,
    decisionForumInvoked: routingSummary.decisionForumInvoked,
    decisionForumMatterRefs: routingSummary.decisionForumMatterRefs,
    queueHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, aiGapQueue) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: aiGapQueue.queueHash,
    artifactType: 'ai_gap_recommendation_queue',
    artifactVersion: input.queueCycle.cycleRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['ai_gap_recommendation', 'drift_management', 'human_review_required', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateAiGapRecommendationQueue(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateQueuePolicy(input?.queuePolicy, reasons);
  evaluateQueueCycle(input?.queueCycle, reasons);
  evaluateAiReviewManifest(input?.aiReviewManifest, input?.queueCycle, reasons);
  const recommendationSummary = evaluateRecommendations(
    input?.recommendations,
    policySummary.requiredGapFamilies,
    input?.queueCycle,
    reasons,
  );
  const queueItemSummary = evaluateQueueItems(
    input?.queueItems,
    recommendationSummary.recommendationRefs,
    policySummary.allowedRouteTypes,
    input?.queueCycle,
    reasons,
  );
  const routingSummary = evaluateDownstreamRouting(
    input?.downstreamRouting,
    queueItemSummary.routeTypes,
    recommendationSummary.materialRecommendationRefs,
    input?.queueCycle,
    input?.queuePolicy,
    reasons,
  );
  evaluateHumanReview(input?.humanReview, input?.queueCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.queueCycle, input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      aiGapQueue: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const aiGapQueue = buildQueue(input, recommendationSummary, queueItemSummary, routingSummary);
  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    aiGapQueue,
    receipt: buildReceipt(input, aiGapQueue),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
