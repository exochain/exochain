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
const LINKAGE_SCHEMA = 'cybermedica.kpi_trend_drift_cqi_linkage.v1';
const REQUIRED_PERMISSION = 'kpi_linkage_manage';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const KPI_DECISION_SCHEMA = 'cybermedica.kpi_management_decision.v1';
const KPI_CYCLE_SCHEMA = 'cybermedica.kpi_management_cycle.v1';
const ALERT_LEVELS = new Set(['critical', 'none', 'warning']);
const KPI_STATUSES = new Set(['below_threshold', 'target_met', 'within_threshold']);
const KPI_TRENDS = new Set(['declining', 'improving', 'not_established', 'unchanged']);
const HUMAN_REVIEW_DECISIONS = new Set(['linkage_accepted', 'observe_only_accepted']);
const SUPPORTED_STATE_TARGETS = new Set(['passport', 'quality_state', 'readiness']);
const SUPPORTED_IMPACT_DOMAINS = new Set(['budget', 'sop', 'stakeholder', 'technology', 'training']);
const ROUTE_TARGETS = Object.freeze(['continuous_quality_improvement', 'drift_improvement']);

const RAW_LINKAGE_FIELDS = new Set([
  'analysisnarrative',
  'freeformanalysis',
  'freetext',
  'kpinarrative',
  'rawanalysis',
  'rawcontent',
  'rawcqi',
  'rawdrift',
  'rawdriftnarrative',
  'rawkpi',
  'rawkpidata',
  'rawmetricdata',
  'rawsource',
  'rawsourcedata',
  'rawtrend',
  'rawtrendnarrative',
  'reviewnotes',
  'trendnarrative',
]);

const SECRET_LINKAGE_FIELDS = new Set([
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

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function assertNoRawLinkageContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawLinkageContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_LINKAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw KPI trend linkage content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_LINKAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`KPI trend linkage secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawLinkageContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawLinkageContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'kpi_linkage_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  const triggerAlertLevels = sortedTextList(policy?.triggerAlertLevels);
  const triggerTrends = sortedTextList(policy?.triggerTrends);

  addReason(reasons, !hasText(policy?.policyRef), 'linkage_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'linkage_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'linkage_policy_not_active');
  addReason(reasons, policy?.driftSignalRequired !== true, 'linkage_policy_drift_signal_rule_absent');
  addReason(reasons, policy?.cqiSourceRequired !== true, 'linkage_policy_cqi_source_rule_absent');
  addReason(reasons, policy?.observeOnlyAllowed !== true, 'linkage_policy_observe_only_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'linkage_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'linkage_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'linkage_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'linkage_policy_after_check');

  for (const level of triggerAlertLevels) {
    addReason(reasons, !ALERT_LEVELS.has(level), `linkage_policy_alert_level_unsupported:${level}`);
  }
  for (const trend of triggerTrends) {
    addReason(reasons, !KPI_TRENDS.has(trend), `linkage_policy_trend_unsupported:${trend}`);
  }
  addReason(reasons, !triggerAlertLevels.includes('critical'), 'linkage_policy_critical_trigger_absent');
  addReason(reasons, !triggerAlertLevels.includes('warning'), 'linkage_policy_warning_trigger_absent');
  addReason(reasons, !triggerTrends.includes('declining'), 'linkage_policy_declining_trigger_absent');

  return { triggerAlertLevels, triggerTrends };
}

function evaluateKpiDecision(kpiDecision, reasons) {
  const kpiCycle = kpiDecision?.kpiCycle;
  const receipt = kpiDecision?.receipt;

  addReason(reasons, kpiDecision?.schema !== KPI_DECISION_SCHEMA, 'kpi_decision_schema_invalid');
  addReason(reasons, kpiDecision?.decision !== 'permitted', 'kpi_decision_not_permitted');
  addReason(reasons, kpiDecision?.failClosed !== false, 'kpi_decision_fail_closed');
  addReason(reasons, kpiDecision?.trustState !== 'inactive', 'kpi_decision_trust_state_invalid');
  addReason(reasons, kpiDecision?.exochainProductionClaim !== false, 'production_trust_claim_forbidden');
  addReason(reasons, kpiCycle?.schema !== KPI_CYCLE_SCHEMA, 'kpi_cycle_schema_invalid');
  addReason(reasons, !hasText(kpiCycle?.kpiId), 'kpi_id_absent');
  addReason(reasons, !hasText(kpiCycle?.periodRef), 'kpi_period_ref_absent');
  addReason(reasons, !isBasisPoints(kpiCycle?.actualBasisPoints), 'kpi_actual_basis_points_invalid');
  addReason(reasons, !isBasisPoints(kpiCycle?.thresholdBasisPoints), 'kpi_threshold_basis_points_invalid');
  addReason(reasons, !isBasisPoints(kpiCycle?.targetBasisPoints), 'kpi_target_basis_points_invalid');
  addReason(reasons, !ALERT_LEVELS.has(kpiCycle?.alertLevel), 'kpi_alert_level_invalid');
  addReason(reasons, !KPI_STATUSES.has(kpiCycle?.status), 'kpi_status_invalid');
  addReason(reasons, !KPI_TRENDS.has(kpiCycle?.trend), 'kpi_trend_invalid');
  addReason(reasons, kpiCycle?.metadataOnly !== true, 'kpi_cycle_metadata_boundary_invalid');
  addReason(reasons, kpiCycle?.immutableMeasurementReceipt !== true, 'kpi_cycle_immutable_receipt_absent');
  addReason(reasons, kpiCycle?.operationalStateMutable !== true, 'kpi_cycle_operational_state_boundary_absent');
  addReason(reasons, !hasText(kpiCycle?.receiptId), 'kpi_cycle_receipt_id_absent');
  addReason(reasons, receipt === null || receipt === undefined, 'kpi_receipt_absent');
  addReason(reasons, receipt?.trustState !== 'inactive', 'kpi_receipt_trust_state_invalid');
  addReason(reasons, receipt?.exochainProductionClaim !== false, 'production_trust_claim_forbidden');
  addReason(reasons, !isDigest(receipt?.actionHash), 'kpi_receipt_action_hash_invalid');
  addReason(reasons, receipt?.anchorPayload?.artifactType !== 'kpi_management_cycle', 'kpi_receipt_artifact_type_invalid');
  addReason(reasons, !isDigest(receipt?.anchorPayload?.artifactHash), 'kpi_receipt_artifact_hash_invalid');
  addReason(reasons, !isDigest(receipt?.anchorPayload?.custodyDigest), 'kpi_receipt_custody_digest_invalid');

  return {
    actualBasisPoints: kpiCycle?.actualBasisPoints ?? null,
    alertLevel: kpiCycle?.alertLevel ?? 'none',
    decisionAction: kpiCycle?.decisionAction ?? null,
    kpiId: kpiCycle?.kpiId ?? null,
    name: kpiCycle?.name ?? null,
    periodRef: kpiCycle?.periodRef ?? null,
    receiptActionHash: receipt?.actionHash ?? null,
    receiptId: kpiCycle?.receiptId ?? null,
    receiptPayloadHash: receipt?.anchorPayload?.artifactHash ?? null,
    riskRefs: sortedTextList(kpiCycle?.riskRefs),
    sourceControlIds: sortedTextList(kpiCycle?.sourceControlIds),
    status: kpiCycle?.status ?? null,
    targetBasisPoints: kpiCycle?.targetBasisPoints ?? null,
    thresholdBasisPoints: kpiCycle?.thresholdBasisPoints ?? null,
    trend: kpiCycle?.trend ?? null,
  };
}

function determineTriggers(kpi, policySummary) {
  const reasons = [];
  if (policySummary.triggerAlertLevels.includes(kpi.alertLevel) && kpi.alertLevel !== 'none') {
    reasons.push(`alert_level:${kpi.alertLevel}`);
  }
  if (kpi.status === 'below_threshold') {
    reasons.push('status:below_threshold');
  }
  if (policySummary.triggerTrends.includes(kpi.trend) && kpi.trend !== 'not_established') {
    reasons.push(`trend:${kpi.trend}`);
  }
  return uniqueSorted(reasons);
}

function evaluateDriftRouting(routing, checkedAtHlc, reasons) {
  if (routing === null || routing === undefined) {
    addReason(reasons, true, 'triggered_kpi_drift_routing_absent');
    return { stateUpdateTargets: [] };
  }

  const stateUpdateTargets = sortedTextList(routing?.stateUpdateTargets);
  addReason(reasons, !hasText(routing?.signalRef), 'drift_signal_ref_absent');
  addReason(reasons, !hasText(routing?.driftCycleRef), 'drift_cycle_ref_absent');
  addReason(reasons, !isDigest(routing?.reviewPathHash), 'drift_review_path_hash_invalid');
  addReason(reasons, !hasText(routing?.ownerRoleRef), 'drift_owner_role_absent');
  addReason(reasons, !isDigest(routing?.ownerDidHash), 'drift_owner_hash_invalid');
  addReason(reasons, !isDigest(routing?.assignmentHash), 'drift_assignment_hash_invalid');
  addReason(reasons, hlcTuple(routing?.assignedAtHlc) === null, 'drift_assignment_time_invalid');
  addReason(reasons, hlcTuple(routing?.dueAtHlc) === null, 'drift_due_time_invalid');
  addReason(reasons, hlcBefore(routing?.assignedAtHlc, checkedAtHlc), 'drift_assignment_before_linkage_check');
  addReason(reasons, hlcBefore(routing?.dueAtHlc, routing?.assignedAtHlc), 'drift_due_before_assignment');
  addReason(reasons, !hasText(routing?.decisionForumMatterRef), 'drift_decision_forum_matter_absent');
  addReason(reasons, stateUpdateTargets.length === 0, 'drift_state_update_targets_absent');
  addReason(reasons, routing?.metadataOnly !== true, 'drift_routing_metadata_boundary_invalid');
  addReason(reasons, routing?.protectedContentExcluded !== true, 'drift_routing_protected_boundary_invalid');

  for (const target of stateUpdateTargets) {
    addReason(reasons, !SUPPORTED_STATE_TARGETS.has(target), `drift_state_update_target_unsupported:${target}`);
  }

  return { stateUpdateTargets };
}

function evaluateCqiRouting(routing, reasons) {
  if (routing === null || routing === undefined) {
    addReason(reasons, true, 'triggered_kpi_cqi_routing_absent');
    return { evidenceRequirementRefs: [], impactDomains: [], relatedProcessRefs: [] };
  }

  const evidenceRequirementRefs = sortedTextList(routing?.evidenceRequirementRefs);
  const impactDomains = sortedTextList(routing?.impactDomains);
  const relatedProcessRefs = sortedTextList(routing?.relatedProcessRefs);

  addReason(reasons, !hasText(routing?.sourceRef), 'cqi_source_ref_absent');
  addReason(reasons, !hasText(routing?.improvementRef), 'cqi_improvement_ref_absent');
  addReason(reasons, !hasText(routing?.cqiPolicyRef), 'cqi_policy_ref_absent');
  addReason(reasons, !isDigest(routing?.problemStatementHash), 'cqi_problem_statement_hash_invalid');
  addReason(reasons, !isDigest(routing?.proposedChangeHash), 'cqi_proposed_change_hash_invalid');
  addReason(reasons, !isDigest(routing?.expectedBenefitHash), 'cqi_expected_benefit_hash_invalid');
  addReason(reasons, !isDigest(routing?.verificationMethodHash), 'cqi_verification_method_hash_invalid');
  addReason(reasons, !hasText(routing?.decisionForumMatterRef), 'cqi_decision_forum_matter_absent');
  addReason(reasons, relatedProcessRefs.length === 0, 'cqi_related_process_refs_absent');
  addReason(reasons, impactDomains.length === 0, 'cqi_impact_domains_absent');
  addReason(reasons, evidenceRequirementRefs.length === 0, 'cqi_evidence_requirement_refs_absent');
  addReason(reasons, !isDigest(routing?.custodyDigest), 'cqi_custody_digest_invalid');
  addReason(reasons, routing?.metadataOnly !== true, 'cqi_routing_metadata_boundary_invalid');
  addReason(reasons, routing?.protectedContentExcluded !== true, 'cqi_routing_protected_boundary_invalid');

  for (const domain of impactDomains) {
    addReason(reasons, !SUPPORTED_IMPACT_DOMAINS.has(domain), `cqi_impact_domain_unsupported:${domain}`);
  }

  return { evidenceRequirementRefs, impactDomains, relatedProcessRefs };
}

function evaluateHumanReview(humanReview, checkedAtHlc, triggered, reasons) {
  addReason(reasons, humanReview?.verified !== true, 'human_review_unverified');
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'human_review_did_absent');
  addReason(reasons, !isDigest(humanReview?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(reasons, triggered && humanReview?.decision !== 'linkage_accepted', 'human_review_linkage_decision_mismatch');
  addReason(reasons, !triggered && humanReview?.decision !== 'observe_only_accepted', 'human_review_observe_decision_mismatch');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(humanReview?.reviewedAtHlc, checkedAtHlc), 'human_review_before_linkage_check');
  addReason(reasons, humanReview?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, humanReview?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return;
  }

  addReason(reasons, aiAssistance?.advisoryOnly !== true, 'ai_advisory_boundary_invalid');
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(aiAssistance?.outputHash), 'ai_output_hash_invalid');
  addReason(reasons, !isDigest(aiAssistance?.limitationHash), 'ai_limitation_hash_invalid');
  addReason(reasons, aiAssistance?.humanReviewed !== true, 'ai_human_review_absent');
}

function positiveDifference(left, right) {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left <= right) {
    return 0;
  }
  return left - right;
}

function clampBasisPoints(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    return 0;
  }
  if (value > 10_000) {
    return 10_000;
  }
  return value;
}

function riskScoreBasisPoints(kpi, triggerReasons) {
  const thresholdDeficit = positiveDifference(kpi.thresholdBasisPoints, kpi.actualBasisPoints);
  const targetDeficit = positiveDifference(kpi.targetBasisPoints, kpi.actualBasisPoints);
  let score = thresholdDeficit + targetDeficit;
  if (triggerReasons.includes('alert_level:critical')) {
    score += 2_500;
  }
  if (triggerReasons.includes('alert_level:warning')) {
    score += 1_000;
  }
  if (triggerReasons.includes('trend:declining')) {
    score += 1_500;
  }
  return clampBasisPoints(score);
}

function buildDriftSignal(input, kpi, routing, triggerReasons) {
  const riskScore = riskScoreBasisPoints(kpi, triggerReasons);
  const riskLevel = triggerReasons.includes('alert_level:critical') ? 'critical' : 'major';
  const urgency = riskLevel === 'critical' ? 'urgent' : 'standard';

  return {
    schema: 'cybermedica.drift_signal.v1',
    signalRef: routing.signalRef,
    signalFamily: 'kpi_trend',
    sourceRef: kpi.receiptId,
    sourceFamily: 'kpi_management',
    sourceHash: kpi.receiptActionHash,
    detectedAtHlc: input.checkedAtHlc,
    affectedControlRefs: kpi.sourceControlIds,
    driftCycleRef: routing.driftCycleRef,
    reviewPathHash: routing.reviewPathHash,
    ownerRoleRef: routing.ownerRoleRef,
    ownerDidHash: routing.ownerDidHash,
    assignmentHash: routing.assignmentHash,
    assignedAtHlc: routing.assignedAtHlc,
    dueAtHlc: routing.dueAtHlc,
    decisionForumMatterRef: routing.decisionForumMatterRef,
    riskLevel,
    urgency,
    riskScoreBasisPoints: riskScore,
    triggerReasons,
    humanVisible: true,
    reviewable: true,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function buildCqiSource(input, kpi, routing) {
  return {
    schema: 'cybermedica.cqi_source.v1',
    sourceRef: routing.sourceRef,
    sourceFamily: 'kpi_trend',
    sourceHash: kpi.receiptActionHash,
    capturedAtHlc: input.checkedAtHlc,
    reviewedByHuman: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    relatedEvidenceRefs: [kpi.receiptId],
  };
}

function buildCqiImprovementSeed(kpi, routing, normalizedRouting) {
  return {
    schema: 'cybermedica.cqi_improvement_seed.v1',
    improvementRef: routing.improvementRef,
    improvementSource: 'kpi_trend',
    cqiPolicyRef: routing.cqiPolicyRef,
    sourceRef: routing.sourceRef,
    kpiId: kpi.kpiId,
    periodRef: kpi.periodRef,
    problemStatementHash: routing.problemStatementHash,
    proposedChangeHash: routing.proposedChangeHash,
    expectedBenefitHash: routing.expectedBenefitHash,
    verificationMethodHash: routing.verificationMethodHash,
    decisionForumMatterRef: routing.decisionForumMatterRef,
    relatedControlRefs: kpi.sourceControlIds,
    relatedRiskRefs: kpi.riskRefs,
    relatedProcessRefs: normalizedRouting.relatedProcessRefs,
    impactDomains: normalizedRouting.impactDomains,
    evidenceRequirementRefs: normalizedRouting.evidenceRequirementRefs,
    metadataOnly: true,
    protectedContentExcluded: true,
    exochainProductionClaim: false,
  };
}

function buildDashboardUpdate(kpi, triggered) {
  return {
    schema: 'cybermedica.kpi_linkage_dashboard_update.v1',
    kpiId: kpi.kpiId,
    periodRef: kpi.periodRef,
    alertLevel: kpi.alertLevel,
    trend: kpi.trend,
    actualBasisPoints: kpi.actualBasisPoints,
    actionRequired: triggered,
    routeTo: triggered ? [...ROUTE_TARGETS] : [],
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildLinkage(input, kpi, triggerReasons, normalized) {
  const triggered = triggerReasons.length > 0;
  const driftSignal = triggered ? buildDriftSignal(input, kpi, input.driftRouting, triggerReasons) : null;
  const cqiSource = triggered ? buildCqiSource(input, kpi, input.cqiRouting) : null;
  const cqiImprovementSeed = triggered ? buildCqiImprovementSeed(kpi, input.cqiRouting, normalized.cqiRouting) : null;

  const basis = {
    cqiSourceRef: cqiSource?.sourceRef ?? null,
    driftSignalRef: driftSignal?.signalRef ?? null,
    kpiId: kpi.kpiId,
    periodRef: kpi.periodRef,
    receiptActionHash: kpi.receiptActionHash,
    tenantId: input.tenantId,
    triggerReasons,
  };

  return {
    schema: LINKAGE_SCHEMA,
    linkageId: `cmkpi_link_${sha256Hex(basis).slice(0, 32)}`,
    tenantId: input.tenantId,
    checkedAtHlc: input.checkedAtHlc,
    policyRef: input.linkagePolicy.policyRef,
    triggered,
    triggerReasons,
    kpi,
    driftSignal,
    cqiSource,
    cqiImprovementSeed,
    dashboardUpdate: buildDashboardUpdate(kpi, triggered),
    humanReview: {
      reviewerDid: input.humanReview.reviewerDid,
      reviewHash: input.humanReview.reviewHash,
      decision: input.humanReview.decision,
      reviewedAtHlc: input.humanReview.reviewedAtHlc,
    },
    driftStateUpdateTargets: normalized.driftRouting.stateUpdateTargets,
    metadataOnly: true,
    protectedContentExcluded: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, linkage) {
  const custodyDigest =
    input.cqiRouting?.custodyDigest ?? input.kpiDecision?.receipt?.anchorPayload?.custodyDigest ?? linkage.kpi.receiptPayloadHash;

  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(linkage),
    artifactType: 'kpi_trend_drift_cqi_linkage',
    artifactVersion: `${linkage.kpi.kpiId}@${linkage.kpi.periodRef}`,
    classification: 'quality_evidence',
    custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['kpi_trend', 'drift_management', 'continuous_quality_improvement', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateKpiTrendDriftCqiLinkage(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluatePolicy(input?.linkagePolicy, input?.checkedAtHlc, reasons);
  const kpi = evaluateKpiDecision(input?.kpiDecision, reasons);
  const triggerReasons = determineTriggers(kpi, policySummary);
  const triggered = triggerReasons.length > 0;
  const normalized = {
    cqiRouting: { evidenceRequirementRefs: [], impactDomains: [], relatedProcessRefs: [] },
    driftRouting: { stateUpdateTargets: [] },
  };

  if (triggered) {
    normalized.driftRouting = evaluateDriftRouting(input?.driftRouting, input?.checkedAtHlc, reasons);
    normalized.cqiRouting = evaluateCqiRouting(input?.cqiRouting, reasons);
  }
  evaluateHumanReview(input?.humanReview, input?.checkedAtHlc, triggered, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: LINKAGE_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      linkage: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const linkage = buildLinkage(input, kpi, triggerReasons, normalized);
  return {
    schema: LINKAGE_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    linkage,
    receipt: buildReceipt(input, linkage),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
