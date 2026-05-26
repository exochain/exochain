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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'kpi_manage';
const KPI_LIFECYCLE_STATES = new Set(['active']);
const MONITORING_STATES = new Set(['reviewed']);
const ANOMALY_DISPOSITIONS = new Set(['none', 'investigate', 'accepted', 'escalated']);
const DECISION_ACTIONS = new Set(['continue_monitoring', 'open_capa', 'decision_forum_review', 'resource_adjustment', 'suspend_enrollment']);
const ESCALATING_DECISION_ACTIONS = new Set(['open_capa', 'decision_forum_review', 'suspend_enrollment']);
const RAW_KPI_FIELDS = new Set([
  'analysisnarrative',
  'freeformanalysis',
  'kpinarrative',
  'metricnotes',
  'rawanalysis',
  'rawkpidata',
  'rawkpinarrative',
  'rawmetricdata',
  'rawreporttext',
  'reportnarrative',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isNonNegativeSafeInteger(value) {
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

function assertNoRawKpiText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawKpiText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_KPI_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw KPI content field is not allowed at ${path}.${key}`);
    }
    assertNoRawKpiText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawKpiText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical) && hlc.logical >= 0;
}

function compareHlc(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs < right.physicalMs ? -1 : 1;
  }
  if (left.logical !== right.logical) {
    return left.logical < right.logical ? -1 : 1;
  }
  return 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value.filter(hasText))].sort();
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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
    'authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateKpiDefinition(input, reasons) {
  const kpi = input?.kpi;
  addReason(reasons, !hasText(kpi?.kpiId), 'kpi_id_absent');
  addReason(reasons, !hasText(kpi?.name), 'kpi_name_absent');
  addReason(reasons, !hasText(kpi?.sourceStrategyRef), 'kpi_source_strategy_absent');
  addReason(reasons, sortedTextList(kpi?.sourceControlIds).length === 0, 'kpi_source_control_linkage_absent');
  addReason(reasons, !hasText(kpi?.definition), 'kpi_definition_absent');
  addReason(reasons, !hasText(kpi?.numeratorDefinition), 'kpi_numerator_definition_absent');
  addReason(reasons, !hasText(kpi?.denominatorDefinition), 'kpi_denominator_definition_absent');
  addReason(reasons, !hasText(kpi?.collectionMethod), 'collection_method_absent');
  addReason(reasons, !hasText(kpi?.frequency), 'frequency_absent');
  addReason(reasons, !hasText(kpi?.ownerDid), 'kpi_owner_absent');
  addReason(reasons, sortedTextList(kpi?.riskRefs).length === 0, 'risk_linkage_absent');
  addReason(reasons, !hasText(kpi?.qualityObjectiveRef), 'quality_objective_ref_absent');
  addReason(reasons, sortedTextList(kpi?.reportingAudience).length === 0, 'reporting_audience_absent');
  addReason(reasons, !hasText(kpi?.decisionUse), 'decision_use_absent');
  addReason(reasons, !KPI_LIFECYCLE_STATES.has(kpi?.lifecycleState), 'kpi_lifecycle_state_invalid');
  addReason(reasons, !isBasisPoints(kpi?.thresholdBasisPoints), 'threshold_basis_points_invalid');
  addReason(reasons, !isBasisPoints(kpi?.targetBasisPoints), 'target_basis_points_invalid');
  if (isBasisPoints(kpi?.thresholdBasisPoints) && isBasisPoints(kpi?.targetBasisPoints)) {
    addReason(reasons, kpi.targetBasisPoints < kpi.thresholdBasisPoints, 'target_below_threshold');
  }

  const warning = kpi?.alertRule?.warningBelowBasisPoints;
  const critical = kpi?.alertRule?.criticalBelowBasisPoints;
  addReason(reasons, !isBasisPoints(warning), 'warning_basis_points_invalid');
  addReason(reasons, !isBasisPoints(critical), 'critical_basis_points_invalid');
  if (isBasisPoints(warning) && isBasisPoints(critical) && isBasisPoints(kpi?.thresholdBasisPoints)) {
    addReason(reasons, critical > warning || warning > kpi.thresholdBasisPoints, 'alert_threshold_order_invalid');
  }
}

function evaluateCollection(input, reasons) {
  const collection = input?.collection;
  const dataSourceRefs = sortedTextList(collection?.dataSourceRefs);
  addReason(reasons, !hasText(collection?.periodRef), 'collection_period_ref_absent');
  addReason(reasons, !hlcPresent(collection?.periodStartHlc), 'collection_period_start_invalid');
  addReason(reasons, !hlcPresent(collection?.periodEndHlc), 'collection_period_end_invalid');
  addReason(
    reasons,
    hlcPresent(collection?.periodStartHlc) &&
      hlcPresent(collection?.periodEndHlc) &&
      compareHlc(collection.periodEndHlc, collection.periodStartHlc) <= 0,
    'collection_period_not_monotonic',
  );
  addReason(reasons, dataSourceRefs.length === 0, 'collection_data_source_absent');
  addReason(reasons, !isDigest(collection?.collectionEvidenceHash), 'collection_evidence_hash_invalid');
  addReason(reasons, !isDigest(collection?.custodyDigest), 'collection_custody_digest_invalid');
  addReason(reasons, collection?.boundary?.metadataOnly !== true, 'collection_metadata_boundary_invalid');
  addReason(reasons, collection?.boundary?.phiBoundaryAttested !== true, 'collection_phi_boundary_unattested');
  addReason(reasons, collection?.boundary?.directIdentifiersExcluded !== true, 'collection_identifier_boundary_invalid');
  addReason(reasons, collection?.boundary?.sourcePayloadAnchored !== false, 'collection_payload_anchor_forbidden');
  return dataSourceRefs;
}

function observationSort(left, right) {
  return String(left.observationId).localeCompare(String(right.observationId));
}

function normalizeObservations(input, dataSourceRefs, reasons) {
  const dataSources = new Set(dataSourceRefs);
  const observations = Array.isArray(input?.observations) ? [...input.observations].sort(observationSort) : [];
  addReason(reasons, observations.length === 0, 'observations_absent');

  return observations.map((observation) => {
    const observationId = hasText(observation?.observationId) ? observation.observationId : 'unknown';
    addReason(reasons, !hasText(observation?.observationId), 'observation_id_absent');
    addReason(reasons, !isNonNegativeSafeInteger(observation?.numerator), `observation_numerator_invalid:${observationId}`);
    addReason(
      reasons,
      !Number.isSafeInteger(observation?.denominator) || observation.denominator <= 0,
      `observation_denominator_invalid:${observationId}`,
    );
    addReason(
      reasons,
      isNonNegativeSafeInteger(observation?.numerator) &&
        Number.isSafeInteger(observation?.denominator) &&
        observation.denominator > 0 &&
        observation.numerator > observation.denominator,
      `observation_numerator_exceeds_denominator:${observationId}`,
    );
    addReason(reasons, !hlcPresent(observation?.measuredAtHlc), `observation_time_invalid:${observationId}`);
    addReason(reasons, !isDigest(observation?.evidenceHash), `observation_evidence_hash_invalid:${observationId}`);
    addReason(reasons, !isDigest(observation?.custodyDigest), `observation_custody_digest_invalid:${observationId}`);
    addReason(reasons, !hasText(observation?.sourceSystemRef), `observation_source_system_absent:${observationId}`);
    addReason(
      reasons,
      hasText(observation?.sourceSystemRef) && dataSources.size > 0 && !dataSources.has(observation.sourceSystemRef),
      `observation_source_system_not_collected:${observationId}`,
    );
    addReason(
      reasons,
      hlcPresent(observation?.measuredAtHlc) &&
        hlcPresent(input?.collection?.periodStartHlc) &&
        compareHlc(observation.measuredAtHlc, input.collection.periodStartHlc) < 0,
      `observation_before_collection_start:${observationId}`,
    );
    addReason(
      reasons,
      hlcPresent(observation?.measuredAtHlc) &&
        hlcPresent(input?.collection?.periodEndHlc) &&
        compareHlc(observation.measuredAtHlc, input.collection.periodEndHlc) > 0,
      `observation_after_collection_end:${observationId}`,
    );

    return {
      custodyDigest: observation?.custodyDigest ?? null,
      denominator: observation?.denominator ?? null,
      evidenceHash: observation?.evidenceHash ?? null,
      measuredAtHlc: observation?.measuredAtHlc ?? null,
      numerator: observation?.numerator ?? null,
      observationId,
      sourceSystemRef: observation?.sourceSystemRef ?? null,
    };
  });
}

function evaluatePreviousCycle(input, reasons) {
  const previous = input?.previousCycle;
  if (previous === null || previous === undefined) {
    return;
  }
  addReason(reasons, !isBasisPoints(previous?.actualBasisPoints), 'previous_cycle_basis_points_invalid');
  addReason(reasons, !hlcPresent(previous?.periodEndHlc), 'previous_cycle_period_end_invalid');
  addReason(
    reasons,
    hlcPresent(previous?.periodEndHlc) &&
      hlcPresent(input?.collection?.periodStartHlc) &&
      compareHlc(previous.periodEndHlc, input.collection.periodStartHlc) >= 0,
    'previous_cycle_not_before_current',
  );
}

function evaluateMonitoring(input, reasons) {
  const monitoring = input?.monitoring;
  addReason(reasons, !hlcPresent(monitoring?.reviewedAtHlc), 'monitoring_review_time_invalid');
  addReason(reasons, !hasText(monitoring?.reviewerDid), 'monitoring_reviewer_absent');
  addReason(reasons, !isDigest(monitoring?.reviewEvidenceHash), 'monitoring_review_evidence_invalid');
  addReason(reasons, !MONITORING_STATES.has(monitoring?.monitoringState), 'monitoring_state_invalid');
  addReason(reasons, !ANOMALY_DISPOSITIONS.has(monitoring?.anomalyDisposition), 'monitoring_anomaly_disposition_invalid');
  addReason(reasons, typeof monitoring?.thresholdBreachAcknowledged !== 'boolean', 'monitoring_threshold_acknowledgement_invalid');
  addReason(
    reasons,
    hlcPresent(monitoring?.reviewedAtHlc) &&
      hlcPresent(input?.collection?.periodEndHlc) &&
      compareHlc(monitoring.reviewedAtHlc, input.collection.periodEndHlc) < 0,
    'monitoring_before_collection_end',
  );
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.advisoryOnly !== true, 'ai_assistance_not_advisory');
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, !hasText(aiAssistance.modelRef), 'ai_assistance_model_absent');
  addReason(reasons, !isDigest(aiAssistance.promptHash), 'ai_assistance_prompt_hash_invalid');
  addReason(reasons, !isDigest(aiAssistance.outputHash), 'ai_assistance_output_hash_invalid');
  addReason(reasons, aiAssistance.humanReviewed !== true, 'ai_assistance_human_review_absent');
}

function evaluateAnalysis(input, reasons) {
  const analysis = input?.analysis;
  addReason(reasons, !hlcPresent(analysis?.analyzedAtHlc), 'analysis_time_invalid');
  addReason(reasons, !hasText(analysis?.methodRef), 'analysis_method_absent');
  addReason(reasons, !isDigest(analysis?.analysisEvidenceHash), 'analysis_evidence_hash_invalid');
  addReason(reasons, !isDigest(analysis?.assumptionHash), 'analysis_assumption_hash_invalid');
  addReason(reasons, !isDigest(analysis?.limitationHash), 'analysis_limitation_hash_invalid');
  addReason(
    reasons,
    hlcPresent(analysis?.analyzedAtHlc) &&
      hlcPresent(input?.monitoring?.reviewedAtHlc) &&
      compareHlc(analysis.analyzedAtHlc, input.monitoring.reviewedAtHlc) < 0,
    'analysis_before_monitoring',
  );
  evaluateAiAssistance(analysis?.aiAssistance, reasons);
}

function evaluateReport(input, reasons) {
  const report = input?.report;
  const recipients = sortedTextList(report?.recipients);
  addReason(reasons, !hasText(report?.reportId), 'report_id_absent');
  addReason(reasons, !hlcPresent(report?.reportedAtHlc), 'report_time_invalid');
  addReason(reasons, !isDigest(report?.reportHash), 'report_hash_invalid');
  addReason(reasons, sortedTextList(report?.dashboardRefs).length === 0, 'report_dashboard_refs_absent');
  addReason(reasons, recipients.length === 0, 'report_recipients_absent');
  addReason(reasons, !isDigest(report?.distributedEvidenceHash), 'report_distribution_evidence_invalid');
  addReason(reasons, report?.phiBoundaryAttested !== true, 'report_phi_boundary_unattested');
  addReason(
    reasons,
    hlcPresent(report?.reportedAtHlc) &&
      hlcPresent(input?.analysis?.analyzedAtHlc) &&
      compareHlc(report.reportedAtHlc, input.analysis.analyzedAtHlc) < 0,
    'report_before_analysis',
  );

  for (const audience of sortedTextList(input?.kpi?.reportingAudience)) {
    addReason(reasons, !recipients.includes(audience), `reporting_audience_not_notified:${audience}`);
  }
}

function decisionForumVerified(decisionForum) {
  return (
    decisionForum?.verified === true &&
    decisionForum?.state === 'approved' &&
    decisionForum?.humanGate?.verified === true &&
    decisionForum?.quorum?.status === 'met' &&
    decisionForum?.openChallenge !== true &&
    hasText(decisionForum?.receiptRef)
  );
}

function evaluateDecisionUse(input, actualBasisPoints, alertLevelValue, reasons) {
  const decisionUse = input?.decisionUse;
  addReason(reasons, !hasText(decisionUse?.decisionMatterRef), 'decision_matter_ref_absent');
  addReason(reasons, !DECISION_ACTIONS.has(decisionUse?.action), 'decision_use_action_invalid');
  addReason(reasons, !isDigest(decisionUse?.rationaleHash), 'decision_use_rationale_hash_invalid');
  addReason(reasons, !hlcPresent(decisionUse?.usedAtHlc), 'decision_use_time_invalid');
  addReason(reasons, !hasText(decisionUse?.ownerDid), 'decision_use_owner_absent');
  addReason(
    reasons,
    hlcPresent(decisionUse?.usedAtHlc) &&
      hlcPresent(input?.report?.reportedAtHlc) &&
      compareHlc(decisionUse.usedAtHlc, input.report.reportedAtHlc) < 0,
    'decision_use_before_report',
  );

  const isCritical = alertLevelValue === 'critical' || actualBasisPoints < input?.kpi?.alertRule?.criticalBelowBasisPoints;
  if (isCritical) {
    addReason(reasons, !ESCALATING_DECISION_ACTIONS.has(decisionUse?.action), 'critical_kpi_requires_escalating_decision_use');
  }

  if (decisionUse?.action === 'open_capa') {
    addReason(reasons, !hasText(decisionUse?.capaRef), 'capa_ref_absent');
    addReason(reasons, !decisionForumVerified(decisionUse?.decisionForum), 'decision_forum_escalation_unverified');
  }

  if (decisionUse?.action === 'decision_forum_review' || decisionUse?.action === 'suspend_enrollment') {
    addReason(reasons, !decisionForumVerified(decisionUse?.decisionForum), 'decision_forum_escalation_unverified');
  }
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function safeTotal(observations, fieldName) {
  let total = 0n;
  for (const observation of observations) {
    total += BigInt(observation[fieldName]);
  }
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(total);
}

function objectiveStatus(actualBasisPoints, kpi) {
  if (actualBasisPoints >= kpi.targetBasisPoints) {
    return 'target_met';
  }
  if (actualBasisPoints >= kpi.thresholdBasisPoints) {
    return 'within_threshold';
  }
  return 'below_threshold';
}

function alertLevel(actualBasisPoints, kpi) {
  if (actualBasisPoints < kpi.alertRule.criticalBelowBasisPoints) {
    return 'critical';
  }
  if (actualBasisPoints < kpi.alertRule.warningBelowBasisPoints) {
    return 'warning';
  }
  return 'none';
}

function trend(actualBasisPoints, previousCycle) {
  if (!previousCycle || !isBasisPoints(previousCycle.actualBasisPoints)) {
    return 'not_established';
  }
  if (actualBasisPoints > previousCycle.actualBasisPoints) {
    return 'improving';
  }
  if (actualBasisPoints < previousCycle.actualBasisPoints) {
    return 'declining';
  }
  return 'unchanged';
}

function requiredEscalationRoles(alertLevelValue, trendValue) {
  if (alertLevelValue === 'critical') {
    return ['decision_forum', 'principal_investigator', 'quality_manager'];
  }
  if (alertLevelValue === 'warning' || trendValue === 'declining') {
    return ['quality_manager'];
  }
  return [];
}

function calculateTotals(observations, reasons) {
  const totalNumerator = safeTotal(observations, 'numerator');
  const totalDenominator = safeTotal(observations, 'denominator');
  addReason(reasons, totalNumerator === null, 'observation_numerator_total_unsafe');
  addReason(reasons, totalDenominator === null, 'observation_denominator_total_unsafe');
  return { totalDenominator, totalNumerator };
}

function buildArtifactHash(input, kpiCycle, normalizedObservations) {
  return sha256Hex({
    actualBasisPoints: kpiCycle.actualBasisPoints,
    alertLevel: kpiCycle.alertLevel,
    analysisEvidenceHash: input.analysis.analysisEvidenceHash,
    collectionEvidenceHash: input.collection.collectionEvidenceHash,
    decisionAction: kpiCycle.decisionAction,
    evidenceHashDigest: kpiCycle.evidenceHashDigest,
    kpiId: kpiCycle.kpiId,
    observationRefs: normalizedObservations.map((observation) => observation.observationId),
    periodRef: kpiCycle.periodRef,
    reportHash: input.report.reportHash,
    status: kpiCycle.status,
    totalDenominator: kpiCycle.totalDenominator,
    totalNumerator: kpiCycle.totalNumerator,
    trend: kpiCycle.trend,
  });
}

function buildReceipt(input, kpiCycle, normalizedObservations) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'kpi_management_cycle',
    artifactVersion: `${input.kpi.kpiId}@${input.collection.periodRef}`,
    artifactHash: buildArtifactHash(input, kpiCycle, normalizedObservations),
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.decisionUse.usedAtHlc,
    custodyDigest: input.collection.custodyDigest,
    sensitivityTags: ['kpi', 'quality_metric', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildKpiCycle(input, normalizedObservations, totalNumerator, totalDenominator) {
  const actualBasisPoints = basisPoints(totalNumerator, totalDenominator);
  const status = objectiveStatus(actualBasisPoints, input.kpi);
  const alertLevelValue = alertLevel(actualBasisPoints, input.kpi);
  const trendValue = trend(actualBasisPoints, input.previousCycle);
  const evidenceHashes = uniqueSorted([
    input.collection.collectionEvidenceHash,
    input.analysis.analysisEvidenceHash,
    input.report.reportHash,
    input.report.distributedEvidenceHash,
    input.monitoring.reviewEvidenceHash,
    ...normalizedObservations.map((observation) => observation.evidenceHash),
  ]);
  const escalationRoles = requiredEscalationRoles(alertLevelValue, trendValue);

  return {
    schema: 'cybermedica.kpi_management_cycle.v1',
    tenantId: input.tenantId,
    kpiId: input.kpi.kpiId,
    name: input.kpi.name,
    sourceStrategyRef: input.kpi.sourceStrategyRef,
    sourceControlIds: sortedTextList(input.kpi.sourceControlIds),
    definition: input.kpi.definition,
    numeratorDefinition: input.kpi.numeratorDefinition,
    denominatorDefinition: input.kpi.denominatorDefinition,
    collectionMethod: input.kpi.collectionMethod,
    frequency: input.kpi.frequency,
    ownerDid: input.kpi.ownerDid,
    thresholdBasisPoints: input.kpi.thresholdBasisPoints,
    targetBasisPoints: input.kpi.targetBasisPoints,
    warningBelowBasisPoints: input.kpi.alertRule.warningBelowBasisPoints,
    criticalBelowBasisPoints: input.kpi.alertRule.criticalBelowBasisPoints,
    riskRefs: sortedTextList(input.kpi.riskRefs),
    qualityObjectiveRef: input.kpi.qualityObjectiveRef,
    reportingAudience: sortedTextList(input.kpi.reportingAudience),
    decisionUse: input.kpi.decisionUse,
    lifecycleState: input.kpi.lifecycleState,
    periodRef: input.collection.periodRef,
    periodStartHlc: input.collection.periodStartHlc,
    periodEndHlc: input.collection.periodEndHlc,
    dataSourceRefs: sortedTextList(input.collection.dataSourceRefs),
    observationRefs: normalizedObservations.map((observation) => observation.observationId),
    observationCount: normalizedObservations.length,
    totalNumerator,
    totalDenominator,
    actualBasisPoints,
    status,
    alertLevel: alertLevelValue,
    trend: trendValue,
    previousActualBasisPoints: input.previousCycle?.actualBasisPoints ?? null,
    monitoringState: input.monitoring.monitoringState,
    anomalyDisposition: input.monitoring.anomalyDisposition,
    reviewedAtHlc: input.monitoring.reviewedAtHlc,
    analyzedAtHlc: input.analysis.analyzedAtHlc,
    reportId: input.report.reportId,
    reportedAtHlc: input.report.reportedAtHlc,
    dashboardRefs: sortedTextList(input.report.dashboardRefs),
    recipients: sortedTextList(input.report.recipients),
    decisionMatterRef: input.decisionUse.decisionMatterRef,
    decisionAction: input.decisionUse.action,
    usedAtHlc: input.decisionUse.usedAtHlc,
    requiredEscalationRoles: escalationRoles,
    evidenceHashDigest: sha256Hex(evidenceHashes),
    observationDigest: sha256Hex(normalizedObservations),
    metadataOnly: true,
    immutableMeasurementReceipt: true,
    operationalStateMutable: true,
  };
}

function buildDashboardItem(kpiCycle) {
  return {
    schema: 'cybermedica.kpi_dashboard_item.v1',
    kpiId: kpiCycle.kpiId,
    periodRef: kpiCycle.periodRef,
    status: kpiCycle.status,
    alertLevel: kpiCycle.alertLevel,
    trend: kpiCycle.trend,
    actualBasisPoints: kpiCycle.actualBasisPoints,
    targetBasisPoints: kpiCycle.targetBasisPoints,
    thresholdBasisPoints: kpiCycle.thresholdBasisPoints,
    actionRequired: kpiCycle.requiredEscalationRoles.length > 0,
    requiredEscalationRoles: kpiCycle.requiredEscalationRoles,
    decisionMatterRef: kpiCycle.decisionMatterRef,
    exochainProductionClaim: false,
    trustState: 'inactive',
  };
}

export function evaluateKpiManagementCycle(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateKpiDefinition(input, reasons);
  const dataSourceRefs = evaluateCollection(input, reasons);
  const normalizedObservations = normalizeObservations(input, dataSourceRefs, reasons);
  evaluatePreviousCycle(input, reasons);
  evaluateMonitoring(input, reasons);
  evaluateAnalysis(input, reasons);
  evaluateReport(input, reasons);

  const { totalDenominator, totalNumerator } = calculateTotals(normalizedObservations, reasons);
  let actualBasisPoints = null;
  let alertLevelValue = null;
  if (Number.isSafeInteger(totalNumerator) && Number.isSafeInteger(totalDenominator) && totalDenominator > 0) {
    actualBasisPoints = basisPoints(totalNumerator, totalDenominator);
    alertLevelValue = alertLevel(actualBasisPoints, input?.kpi);
    evaluateDecisionUse(input, actualBasisPoints, alertLevelValue, reasons);
  } else {
    evaluateDecisionUse(input, 0, 'critical', reasons);
  }

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.kpi_management_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      kpiCycle: null,
      dashboardItem: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const kpiCycle = buildKpiCycle(input, normalizedObservations, totalNumerator, totalDenominator);
  const receipt = buildReceipt(input, kpiCycle, normalizedObservations);
  kpiCycle.receiptId = receipt.receiptId;

  return {
    schema: 'cybermedica.kpi_management_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    kpiCycle,
    dashboardItem: buildDashboardItem(kpiCycle),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
