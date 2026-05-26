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
const SCALABILITY_CAPACITY_SCHEMA = 'cybermedica.scalability_capacity.v1';
const SCALABILITY_CAPACITY_RECORD_SCHEMA = 'cybermedica.scalability_capacity_record.v1';
const MAX_BASIS_POINTS = 10000;

const REQUIRED_DIMENSIONS = Object.freeze([
  'cro_portfolios',
  'decision_records',
  'evidence_volumes',
  'networks',
  'sites',
  'sponsors',
  'studies',
]);

const REQUIRED_CONTROL_FAMILIES = Object.freeze([
  'access_policy_partitioning',
  'archive_retention_partitioning',
  'backpressure',
  'bulk_import_throttling',
  'decision_queue_sharding',
  'evidence_index_partitioning',
  'pagination_cursoring',
]);

const REQUIRED_MONITORING_SIGNALS = Object.freeze([
  'api_request_queue',
  'decision_queue_depth',
  'evidence_ingestion_backlog',
  'export_job_backlog',
  'portfolio_dashboard_latency',
  'receipt_write_latency',
]);

const RAW_CAPACITY_FIELDS = new Set([
  'capacitymodelbody',
  'capacitynarrative',
  'freetextcapacitynote',
  'loadtestrawpayload',
  'rawcapacity',
  'rawcapacitypayload',
  'rawforecast',
  'rawloadevidence',
  'rawmonitoringdata',
  'rawpayload',
  'rawscaleplan',
  'rawsourcecontent',
  'rawworkload',
  'rawworkloadpayload',
  'sourcedatabody',
  'workloadpayload',
]);

const SECRET_CAPACITY_FIELDS = new Set([
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

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawCapacityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawCapacityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CAPACITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw scalability capacity content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CAPACITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`scalability capacity secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawCapacityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawCapacityContent(input ?? {});
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

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) <= 0;
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_capacity_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'scalability_capacity_manage') && !hasAuthorityPermission(input?.authority, 'govern'),
    'capacity_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizeScalePlan(input, reasons) {
  const plan = input?.scalePlan;
  addReason(reasons, !hasText(plan?.planRef), 'scale_plan_ref_absent');
  addReason(reasons, !hasText(plan?.planVersion), 'scale_plan_version_absent');
  addReason(reasons, plan?.schemaVersion !== SCALABILITY_CAPACITY_SCHEMA, 'scale_plan_schema_invalid');
  addReason(reasons, plan?.status !== 'approved', 'scale_plan_not_approved');
  addReason(reasons, !hasText(plan?.tenantConfigurationRef), 'tenant_configuration_ref_absent');
  addReason(reasons, !hasText(plan?.availabilityReadinessRef), 'availability_readiness_ref_absent');
  addReason(reasons, !isDigest(plan?.capacityModelHash), 'capacity_model_hash_invalid');
  addReason(reasons, !isDigest(plan?.loadTestEvidenceHash), 'load_test_evidence_hash_invalid');
  addReason(reasons, !isDigest(plan?.partitionStrategyHash), 'partition_strategy_hash_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, plan?.metadataOnly !== true, 'scale_plan_metadata_boundary_invalid');

  return {
    availabilityReadinessRef: plan?.availabilityReadinessRef ?? null,
    capacityModelHash: plan?.capacityModelHash ?? null,
    loadTestEvidenceHash: plan?.loadTestEvidenceHash ?? null,
    partitionStrategyHash: plan?.partitionStrategyHash ?? null,
    planRef: hasText(plan?.planRef) ? plan.planRef : 'SCALE-PLAN-UNKNOWN',
    planVersion: hasText(plan?.planVersion) ? plan.planVersion : 'VERSION-UNKNOWN',
    schemaVersion: plan?.schemaVersion ?? null,
    status: plan?.status ?? null,
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

function normalizeScopeDimensions(input, reasons) {
  const dimensions = Array.isArray(input?.scopeDimensions) ? [...input.scopeDimensions].sort(sortByField('dimension')) : [];
  const presentDimensions = uniqueSorted(dimensions.map((dimension) => dimension?.dimension).filter(hasText));
  addReason(reasons, dimensions.length === 0, 'scope_dimensions_absent');
  for (const required of REQUIRED_DIMENSIONS) {
    addReason(reasons, !presentDimensions.includes(required), `required_scope_dimension_missing:${required}`);
  }

  return dimensions.map((dimension) => {
    const dimensionName = hasText(dimension?.dimension) ? dimension.dimension : 'dimension_unknown';
    addReason(reasons, !REQUIRED_DIMENSIONS.includes(dimensionName), `scope_dimension_invalid:${dimensionName}`);
    addReason(reasons, !hasText(dimension?.scopeRef), `scope_ref_absent:${dimensionName}`);
    addReason(reasons, !isDigest(dimension?.inventoryHash), `scope_inventory_hash_invalid:${dimensionName}`);
    addReason(reasons, !isDigest(dimension?.accessPolicyHash), `scope_access_policy_hash_invalid:${dimensionName}`);
    addReason(reasons, dimension?.tenantPartitioned !== true, `scope_not_tenant_partitioned:${dimensionName}`);
    addReason(reasons, dimension?.metadataOnly !== true, `scope_metadata_boundary_invalid:${dimensionName}`);

    return {
      accessPolicyHash: dimension?.accessPolicyHash ?? null,
      dimension: dimensionName,
      inventoryHash: dimension?.inventoryHash ?? null,
      scopeRef: dimension?.scopeRef ?? null,
      tenantPartitioned: dimension?.tenantPartitioned === true,
    };
  });
}

function normalizeOperatingLimits(input, reasons) {
  const limits = Array.isArray(input?.operatingLimits) ? [...input.operatingLimits].sort(sortByField('dimension')) : [];
  const presentDimensions = uniqueSorted(limits.map((limit) => limit?.dimension).filter(hasText));
  addReason(reasons, limits.length === 0, 'operating_limits_absent');
  for (const required of REQUIRED_DIMENSIONS) {
    addReason(reasons, !presentDimensions.includes(required), `required_operating_limit_missing:${required}`);
  }

  return limits.map((limit) => {
    const dimension = hasText(limit?.dimension) ? limit.dimension : 'dimension_unknown';
    addReason(reasons, !REQUIRED_DIMENSIONS.includes(dimension), `operating_limit_dimension_invalid:${dimension}`);
    addReason(reasons, !isPositiveSafeInteger(limit?.hardLimit), `hard_limit_invalid:${dimension}`);
    addReason(reasons, !isBasisPoints(limit?.warningBasisPoints), `warning_basis_points_invalid:${dimension}`);
    addReason(reasons, !isBasisPoints(limit?.criticalBasisPoints), `critical_basis_points_invalid:${dimension}`);
    addReason(
      reasons,
      isBasisPoints(limit?.warningBasisPoints) &&
        isBasisPoints(limit?.criticalBasisPoints) &&
        (limit.warningBasisPoints >= limit.criticalBasisPoints || limit.criticalBasisPoints > MAX_BASIS_POINTS),
      `capacity_threshold_order_invalid:${dimension}`,
    );
    addReason(reasons, !hasText(limit?.scaleActionRef), `scale_action_ref_absent:${dimension}`);
    addReason(reasons, !hasText(limit?.ownerRoleRef), `limit_owner_role_absent:${dimension}`);
    addReason(reasons, limit?.failClosedWhenExceeded !== true, `limit_fail_closed_missing:${dimension}`);
    addReason(reasons, limit?.metadataOnly !== true, `operating_limit_metadata_boundary_invalid:${dimension}`);

    return {
      criticalBasisPoints: limit?.criticalBasisPoints ?? null,
      dimension,
      failClosedWhenExceeded: limit?.failClosedWhenExceeded === true,
      governedScaleActionEvidenceHash: limit?.governedScaleActionEvidenceHash ?? null,
      hardLimit: Number.isSafeInteger(limit?.hardLimit) ? limit.hardLimit : null,
      ownerRoleRef: limit?.ownerRoleRef ?? null,
      scaleActionRef: limit?.scaleActionRef ?? null,
      warningBasisPoints: limit?.warningBasisPoints ?? null,
    };
  });
}

function normalizeWorkloadForecasts(input, reasons) {
  const forecasts = Array.isArray(input?.workloadForecasts) ? [...input.workloadForecasts].sort(sortByField('dimension')) : [];
  const presentDimensions = uniqueSorted(forecasts.map((forecast) => forecast?.dimension).filter(hasText));
  addReason(reasons, forecasts.length === 0, 'workload_forecasts_absent');
  for (const required of REQUIRED_DIMENSIONS) {
    addReason(reasons, !presentDimensions.includes(required), `required_workload_forecast_missing:${required}`);
  }

  return forecasts.map((forecast) => {
    const dimension = hasText(forecast?.dimension) ? forecast.dimension : 'dimension_unknown';
    addReason(reasons, !REQUIRED_DIMENSIONS.includes(dimension), `workload_forecast_dimension_invalid:${dimension}`);
    addReason(reasons, !isNonNegativeSafeInteger(forecast?.currentCount), `current_count_invalid:${dimension}`);
    addReason(reasons, !isNonNegativeSafeInteger(forecast?.projectedCount), `projected_count_invalid:${dimension}`);
    addReason(reasons, !isNonNegativeSafeInteger(forecast?.peakCount), `peak_count_invalid:${dimension}`);
    addReason(
      reasons,
      isNonNegativeSafeInteger(forecast?.currentCount) &&
        isNonNegativeSafeInteger(forecast?.projectedCount) &&
        forecast.projectedCount < forecast.currentCount,
      `projected_count_below_current:${dimension}`,
    );
    addReason(
      reasons,
      isNonNegativeSafeInteger(forecast?.projectedCount) &&
        isNonNegativeSafeInteger(forecast?.peakCount) &&
        forecast.peakCount < forecast.projectedCount,
      `peak_count_below_projected:${dimension}`,
    );
    addReason(reasons, !isPositiveSafeInteger(forecast?.forecastWindowDays), `forecast_window_invalid:${dimension}`);
    addReason(reasons, !isDigest(forecast?.evidenceHash), `forecast_evidence_hash_invalid:${dimension}`);
    addReason(reasons, forecast?.metadataOnly !== true, `forecast_metadata_boundary_invalid:${dimension}`);

    return {
      currentCount: Number.isSafeInteger(forecast?.currentCount) ? forecast.currentCount : null,
      dimension,
      evidenceHash: forecast?.evidenceHash ?? null,
      forecastWindowDays: forecast?.forecastWindowDays ?? null,
      peakCount: Number.isSafeInteger(forecast?.peakCount) ? forecast.peakCount : null,
      projectedCount: Number.isSafeInteger(forecast?.projectedCount) ? forecast.projectedCount : null,
    };
  });
}

function normalizeCapacityControls(input, governanceReview, reasons) {
  const controls = Array.isArray(input?.capacityControls) ? [...input.capacityControls].sort(sortByField('controlFamily')) : [];
  const presentControls = uniqueSorted(controls.map((control) => control?.controlFamily).filter(hasText));
  addReason(reasons, controls.length === 0, 'capacity_controls_absent');
  for (const required of REQUIRED_CONTROL_FAMILIES) {
    addReason(reasons, !presentControls.includes(required), `required_capacity_control_missing:${required}`);
  }

  return controls.map((control) => {
    const controlFamily = hasText(control?.controlFamily) ? control.controlFamily : 'control_unknown';
    addReason(reasons, !REQUIRED_CONTROL_FAMILIES.includes(controlFamily), `capacity_control_family_invalid:${controlFamily}`);
    addReason(reasons, !hasText(control?.controlRef), `capacity_control_ref_absent:${controlFamily}`);
    addReason(reasons, control?.status !== 'approved', `capacity_control_not_approved:${controlFamily}`);
    addReason(reasons, !isDigest(control?.evidenceHash), `capacity_control_evidence_hash_invalid:${controlFamily}`);
    addReason(reasons, hlcTuple(control?.testedAtHlc) === null, `capacity_control_test_time_invalid:${controlFamily}`);
    addReason(
      reasons,
      hlcTuple(control?.testedAtHlc) !== null &&
        hlcTuple(governanceReview.approvedAtHlc) !== null &&
        hlcBefore(control.testedAtHlc, governanceReview.approvedAtHlc),
      `capacity_control_test_before_governance_approval:${controlFamily}`,
    );
    addReason(reasons, !hasText(control?.ownerRoleRef), `capacity_control_owner_absent:${controlFamily}`);
    addReason(reasons, control?.metadataOnly !== true, `capacity_control_metadata_boundary_invalid:${controlFamily}`);

    return {
      controlFamily,
      controlRef: control?.controlRef ?? null,
      evidenceHash: control?.evidenceHash ?? null,
      ownerRoleRef: control?.ownerRoleRef ?? null,
      status: control?.status ?? null,
      testedAtHlc: control?.testedAtHlc ?? null,
    };
  });
}

function normalizeMonitoringSignals(input, governanceReview, reasons) {
  const signals = Array.isArray(input?.monitoringSignals) ? [...input.monitoringSignals].sort(sortByField('signalFamily')) : [];
  const presentSignals = uniqueSorted(signals.map((signal) => signal?.signalFamily).filter(hasText));
  addReason(reasons, signals.length === 0, 'monitoring_signals_absent');
  for (const required of REQUIRED_MONITORING_SIGNALS) {
    addReason(reasons, !presentSignals.includes(required), `required_monitoring_signal_missing:${required}`);
  }

  return signals.map((signal) => {
    const signalFamily = hasText(signal?.signalFamily) ? signal.signalFamily : 'signal_unknown';
    addReason(reasons, !REQUIRED_MONITORING_SIGNALS.includes(signalFamily), `monitoring_signal_family_invalid:${signalFamily}`);
    addReason(reasons, !hasText(signal?.signalRef), `monitoring_signal_ref_absent:${signalFamily}`);
    addReason(reasons, signal?.status !== 'passing', `monitoring_signal_not_passing:${signalFamily}`);
    addReason(reasons, !isBasisPoints(signal?.thresholdBasisPoints), `monitoring_threshold_invalid:${signalFamily}`);
    addReason(reasons, !isBasisPoints(signal?.currentBasisPoints), `monitoring_current_invalid:${signalFamily}`);
    addReason(
      reasons,
      isBasisPoints(signal?.thresholdBasisPoints) && isBasisPoints(signal?.currentBasisPoints) && signal.currentBasisPoints > signal.thresholdBasisPoints,
      `monitoring_signal_over_threshold:${signalFamily}`,
    );
    addReason(reasons, hlcTuple(signal?.observedAtHlc) === null, `monitoring_observed_time_invalid:${signalFamily}`);
    addReason(
      reasons,
      hlcTuple(signal?.observedAtHlc) !== null &&
        hlcTuple(governanceReview.approvedAtHlc) !== null &&
        hlcBefore(signal.observedAtHlc, governanceReview.approvedAtHlc),
      `monitoring_observed_before_governance_approval:${signalFamily}`,
    );
    addReason(reasons, !isDigest(signal?.evidenceHash), `monitoring_evidence_hash_invalid:${signalFamily}`);
    addReason(reasons, signal?.metadataOnly !== true, `monitoring_signal_metadata_boundary_invalid:${signalFamily}`);

    return {
      currentBasisPoints: signal?.currentBasisPoints ?? null,
      evidenceHash: signal?.evidenceHash ?? null,
      observedAtHlc: signal?.observedAtHlc ?? null,
      signalFamily,
      signalRef: signal?.signalRef ?? null,
      status: signal?.status ?? null,
      thresholdBasisPoints: signal?.thresholdBasisPoints ?? null,
    };
  });
}

function normalizeDegradationPlan(input, governanceReview, reasons) {
  const plan = input?.degradationPlan;
  addReason(reasons, !isDigest(plan?.planHash), 'degradation_plan_hash_invalid');
  addReason(reasons, plan?.failClosedOnLimitExceeded !== true, 'degradation_fail_closed_missing');
  addReason(reasons, !isDigest(plan?.writeThrottlingPolicyHash), 'write_throttling_policy_hash_invalid');
  addReason(reasons, !isDigest(plan?.readOnlyModePolicyHash), 'read_only_mode_policy_hash_invalid');
  addReason(reasons, plan?.auditTrailPreserved !== true, 'degradation_audit_trail_not_preserved');
  addReason(reasons, plan?.decisionRecordsPreserved !== true, 'degradation_decision_records_not_preserved');
  addReason(reasons, plan?.participantSafetyBypassForbidden !== true, 'participant_safety_bypass_not_forbidden');
  addReason(reasons, hlcTuple(plan?.testedAtHlc) === null, 'degradation_test_time_invalid');
  addReason(
    reasons,
    hlcTuple(plan?.testedAtHlc) !== null &&
      hlcTuple(governanceReview.approvedAtHlc) !== null &&
      hlcBeforeOrEqual(plan.testedAtHlc, governanceReview.approvedAtHlc),
    'degradation_test_before_governance_approval',
  );
  addReason(reasons, plan?.metadataOnly !== true, 'degradation_plan_metadata_boundary_invalid');

  return {
    auditTrailPreserved: plan?.auditTrailPreserved === true,
    decisionRecordsPreserved: plan?.decisionRecordsPreserved === true,
    failClosedOnLimitExceeded: plan?.failClosedOnLimitExceeded === true,
    participantSafetyBypassForbidden: plan?.participantSafetyBypassForbidden === true,
    planHash: plan?.planHash ?? null,
    readOnlyModePolicyHash: plan?.readOnlyModePolicyHash ?? null,
    testedAtHlc: plan?.testedAtHlc ?? null,
    writeThrottlingPolicyHash: plan?.writeThrottlingPolicyHash ?? null,
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

function mapByDimension(rows) {
  return new Map(rows.map((row) => [row.dimension, row]));
}

function evaluateCapacityUtilization(limits, forecasts, reasons) {
  const limitsByDimension = mapByDimension(limits);
  const forecastsByDimension = mapByDimension(forecasts);
  const utilizationByDimension = {};

  for (const dimension of REQUIRED_DIMENSIONS) {
    const limit = limitsByDimension.get(dimension);
    const forecast = forecastsByDimension.get(dimension);
    if (!limit || !forecast || !isPositiveSafeInteger(limit.hardLimit) || !isNonNegativeSafeInteger(forecast.peakCount)) {
      continue;
    }

    const currentBasisPoints = basisPoints(forecast.currentCount, limit.hardLimit);
    const projectedBasisPoints = basisPoints(forecast.projectedCount, limit.hardLimit);
    const peakBasisPoints = basisPoints(forecast.peakCount, limit.hardLimit);
    addReason(reasons, forecast.peakCount > limit.hardLimit, `capacity_limit_exceeded:${dimension}`);
    addReason(
      reasons,
      isNonNegativeSafeInteger(peakBasisPoints) &&
        isBasisPoints(limit.criticalBasisPoints) &&
        peakBasisPoints >= limit.criticalBasisPoints &&
        !isDigest(limit.governedScaleActionEvidenceHash),
      `critical_capacity_requires_governed_scale_action:${dimension}`,
    );

    utilizationByDimension[dimension] = {
      currentBasisPoints,
      currentCount: forecast.currentCount,
      hardLimit: limit.hardLimit,
      peakBasisPoints,
      peakCount: forecast.peakCount,
      projectedBasisPoints,
      projectedCount: forecast.projectedCount,
    };
  }

  return utilizationByDimension;
}

function alertStates(utilizationByDimension, limits) {
  const limitsByDimension = mapByDimension(limits);
  return Object.entries(utilizationByDimension)
    .flatMap(([dimension, utilization]) => {
      const limit = limitsByDimension.get(dimension);
      if (isBasisPoints(limit.criticalBasisPoints) && utilization.peakBasisPoints >= limit.criticalBasisPoints) {
        return [{ peakBasisPoints: utilization.peakBasisPoints, state: `${dimension}:critical` }];
      }
      if (isBasisPoints(limit.warningBasisPoints) && utilization.peakBasisPoints >= limit.warningBasisPoints) {
        return [{ peakBasisPoints: utilization.peakBasisPoints, state: `${dimension}:warning` }];
      }
      return [];
    })
    .sort((left, right) => {
      if (left.peakBasisPoints !== right.peakBasisPoints) {
        return right.peakBasisPoints - left.peakBasisPoints;
      }
      return left.state.localeCompare(right.state);
    })
    .map((alert) => alert.state);
}

function highestPeakBasisPoints(utilizationByDimension) {
  const peaks = Object.values(utilizationByDimension)
    .map((utilization) => utilization.peakBasisPoints)
    .filter((value) => Number.isSafeInteger(value));
  return peaks.length === 0 ? null : peaks.sort((left, right) => right - left)[0];
}

function capacityMaterial(input, sections, utilizationByDimension, alerts) {
  const dimensionCoverage = uniqueSorted(sections.scopeDimensions.map((dimension) => dimension.dimension));
  const controlCoverage = uniqueSorted(sections.capacityControls.map((control) => control.controlFamily));
  const monitoringCoverage = uniqueSorted(sections.monitoringSignals.map((signal) => signal.signalFamily));
  return {
    aiAssistance: sections.aiAssistance,
    capacityControls: sections.capacityControls,
    controlCoverage,
    degradationPlan: sections.degradationPlan,
    dimensionCoverage,
    governanceReview: sections.governanceReview,
    highestPeakBasisPoints: highestPeakBasisPoints(utilizationByDimension),
    monitoringCoverage,
    monitoringSignals: sections.monitoringSignals,
    operatingLimits: sections.operatingLimits,
    recordSchema: SCALABILITY_CAPACITY_RECORD_SCHEMA,
    scalePlan: sections.scalePlan,
    scopeDimensions: sections.scopeDimensions,
    targetTenantId: input.targetTenantId,
    tenantId: input.tenantId,
    utilizationByDimension,
    workloadForecasts: sections.workloadForecasts,
    alertStates: alerts,
  };
}

function buildCapacityRecord(input, capacityHash, material) {
  return {
    schema: SCALABILITY_CAPACITY_RECORD_SCHEMA,
    aiAssistance: material.aiAssistance,
    alertStates: material.alertStates,
    capacityHash,
    controlCoverage: material.controlCoverage,
    dimensionCoverage: material.dimensionCoverage,
    exochainProductionClaim: false,
    governanceReview: material.governanceReview,
    highestPeakBasisPoints: material.highestPeakBasisPoints,
    monitoringCoverage: material.monitoringCoverage,
    planRef: material.scalePlan.planRef,
    planVersion: material.scalePlan.planVersion,
    status: 'approved',
    tenantId: input.tenantId,
    trustState: 'inactive',
    utilizationByDimension: material.utilizationByDimension,
  };
}

function buildReceipt(input, sections, capacityHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'scalability_capacity',
    artifactVersion: `${sections.scalePlan.planRef}@${sections.scalePlan.planVersion}`,
    artifactHash: capacityHash,
    classification: 'restricted_metadata_only',
    hlcTimestamp: sections.governanceReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['capacity_metadata', 'portfolio_scalability', 'tenant_boundary'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateScalabilityCapacity(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const scalePlan = normalizeScalePlan(input, reasons);
  const governanceReview = normalizeGovernanceReview(input, reasons);
  const scopeDimensions = normalizeScopeDimensions(input, reasons);
  const operatingLimits = normalizeOperatingLimits(input, reasons);
  const workloadForecasts = normalizeWorkloadForecasts(input, reasons);
  const capacityControls = normalizeCapacityControls(input, governanceReview, reasons);
  const monitoringSignals = normalizeMonitoringSignals(input, governanceReview, reasons);
  const degradationPlan = normalizeDegradationPlan(input, governanceReview, reasons);
  const aiAssistance = normalizeAiAssistance(input, reasons);

  let finalReasons = uniqueReasons(reasons);
  const utilizationByDimension = evaluateCapacityUtilization(operatingLimits, workloadForecasts, finalReasons);
  const alerts = alertStates(utilizationByDimension, operatingLimits);
  const dimensionCoverage = uniqueSorted(scopeDimensions.map((dimension) => dimension.dimension));
  const controlCoverage = uniqueSorted(capacityControls.map((control) => control.controlFamily));
  const monitoringCoverage = uniqueSorted(monitoringSignals.map((signal) => signal.signalFamily));
  addReason(finalReasons, !includesAll(REQUIRED_DIMENSIONS, dimensionCoverage), 'dimension_coverage_incomplete');
  addReason(finalReasons, !includesAll(REQUIRED_CONTROL_FAMILIES, controlCoverage), 'capacity_control_coverage_incomplete');
  addReason(finalReasons, !includesAll(REQUIRED_MONITORING_SIGNALS, monitoringCoverage), 'monitoring_coverage_incomplete');

  finalReasons = uniqueReasons(finalReasons);
  if (finalReasons.length > 0) {
    return {
      permitted: false,
      reasons: finalReasons,
      capacityRecord: null,
      receipt: null,
    };
  }

  const sections = {
    aiAssistance,
    capacityControls,
    degradationPlan,
    governanceReview,
    monitoringSignals,
    operatingLimits,
    scalePlan,
    scopeDimensions,
    workloadForecasts,
  };
  const material = capacityMaterial(input, sections, utilizationByDimension, alerts);
  const capacityHash = sha256Hex(material);
  const capacityRecord = buildCapacityRecord(input, capacityHash, material);

  return {
    permitted: true,
    reasons: [],
    capacityRecord,
    receipt: buildReceipt(input, sections, capacityHash),
  };
}
