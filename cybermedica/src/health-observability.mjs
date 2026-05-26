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
const HEALTH_OBSERVABILITY_SCHEMA = 'cybermedica.health_observability_readiness.v1';
const REQUIRED_PERMISSION = 'health_observability_review';
const MAX_BASIS_POINTS = 10000;
const ERROR_BUDGET_MINIMUM_BASIS_POINTS = 9000;

const REQUIRED_HEALTH_CHECKS = Object.freeze([
  'decision_forum',
  'dependency_health',
  'privacy_boundary',
  'process_health',
  'receipt_queue',
  'root_bundle_provider',
  'trust_readiness',
]);

const REQUIRED_OBSERVABILITY_SIGNALS = Object.freeze([
  'audit_event_flow',
  'decision_forum_latency',
  'dependency_status',
  'error_budget',
  'privacy_boundary',
  'process_uptime',
  'receipt_queue_depth',
  'trust_readiness_state',
]);

const REQUIRED_TELEMETRY_BOUNDARIES = Object.freeze([
  'audit_log_redaction',
  'debug_output_redaction',
  'health_payload_redaction',
  'log_payload_redaction',
  'metric_label_minimization',
  'trace_payload_redaction',
]);

const REQUIRED_INCIDENT_RUNBOOKS = Object.freeze([
  'adapter_degraded',
  'decision_forum_degraded',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
]);

const POLICY_STATUSES = new Set(['active']);
const HEALTH_CHECK_STATUSES = new Set(['passing']);
const OBSERVABILITY_SIGNAL_STATUSES = new Set(['active']);
const TELEMETRY_BOUNDARY_STATUSES = new Set(['verified']);
const INCIDENT_RUNBOOK_STATUSES = new Set(['approved', 'tested']);
const HUMAN_REVIEW_DECISIONS = new Set(['accepted_inactive_trust', 'hold_for_observability_gap']);

const RAW_OBSERVABILITY_FIELDS = new Set([
  'debugpayload',
  'debugresponse',
  'freetext',
  'freetextnote',
  'healthpayload',
  'incidentnarrative',
  'logbody',
  'observabilitypayload',
  'rawdebugoutput',
  'rawhealthcontent',
  'rawhealthresponse',
  'rawincident',
  'rawlog',
  'rawmetriclabel',
  'rawobservabilitydata',
  'rawpayload',
  'rawtelemetry',
  'rawtelemetrypayload',
  'runbookbody',
  'runbooktext',
  'sourcebody',
  'sourcedocumentbody',
  'tracepayload',
]);

const SECRET_OBSERVABILITY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

function assertNoRawObservabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawObservabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_OBSERVABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw health observability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_OBSERVABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`health observability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawObservabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawObservabilityContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function integerBasisPoints(present, total) {
  if (!Number.isSafeInteger(present) || !Number.isSafeInteger(total) || total <= 0 || present <= 0) {
    return 0;
  }
  return Number((BigInt(present) * 10000n) / BigInt(total));
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

function latestHlc(values) {
  let latest = null;
  for (const hlc of values) {
    const tuple = hlcTuple(hlc);
    if (tuple === null) {
      continue;
    }
    if (latest === null || compareHlc(tuple, latest) > 0) {
      latest = tuple;
    }
  }
  return latest === null ? null : { physicalMs: latest[0], logical: latest[1] };
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredTextSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_health_observability_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'health_observability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'observability_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'observability_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'observability_policy_not_active');
  addReason(reasons, policy?.healthAndTrustSeparated !== true, 'health_trust_separation_absent');
  addReason(reasons, policy?.noProtectedContentInSignals !== true, 'protected_signal_guard_absent');
  addReason(reasons, policy?.noProductionTrustClaimWithoutActivation !== true, 'production_claim_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'observability_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'observability_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'observability_policy_time_invalid');

  evaluateRequiredTextSet(
    sortedTextList(policy?.requiredHealthChecks),
    REQUIRED_HEALTH_CHECKS,
    'policy_health_check_missing',
    'policy_health_check_unsupported',
    reasons,
  );
  evaluateRequiredTextSet(
    sortedTextList(policy?.requiredObservabilitySignals),
    REQUIRED_OBSERVABILITY_SIGNALS,
    'policy_observability_signal_missing',
    'policy_observability_signal_unsupported',
    reasons,
  );
  evaluateRequiredTextSet(
    sortedTextList(policy?.requiredTelemetryBoundaries),
    REQUIRED_TELEMETRY_BOUNDARIES,
    'policy_telemetry_boundary_missing',
    'policy_telemetry_boundary_unsupported',
    reasons,
  );
  evaluateRequiredTextSet(
    sortedTextList(policy?.requiredIncidentRunbooks),
    REQUIRED_INCIDENT_RUNBOOKS,
    'policy_incident_runbook_missing',
    'policy_incident_runbook_unsupported',
    reasons,
  );
}

function evaluateService(service, reasons) {
  addReason(reasons, !hasText(service?.serviceRef), 'service_ref_absent');
  addReason(reasons, !hasText(service?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, !hasText(service?.environmentRef), 'environment_ref_absent');
  addReason(reasons, !hasText(service?.ownerDid), 'service_owner_absent');
  addReason(reasons, !hasText(service?.backupOwnerDid), 'service_backup_owner_absent');
  addReason(reasons, !hasText(service?.healthEndpointRef), 'health_endpoint_ref_absent');
  addReason(reasons, !hasText(service?.telemetryDestinationRef), 'telemetry_destination_ref_absent');
  addReason(reasons, !hasText(service?.alertRouteRef), 'alert_route_ref_absent');
  addReason(reasons, !hasText(service?.dashboardRef), 'dashboard_ref_absent');
  addReason(reasons, !isDigest(service?.serviceMapHash), 'service_map_hash_invalid');
  addReason(reasons, service?.metadataOnly !== true, 'service_metadata_boundary_invalid');
  addReason(reasons, service?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function firstByFamily(values, familyKey, duplicatePrefix, reasons) {
  const byFamily = new Map();
  for (const value of Array.isArray(values) ? values : []) {
    const family = value?.[familyKey];
    if (!hasText(family)) {
      continue;
    }
    if (byFamily.has(family)) {
      addReason(reasons, true, `${duplicatePrefix}:${family}`);
      continue;
    }
    byFamily.set(family, value);
  }
  return byFamily;
}

function evaluateHealthChecks(checks, reasons) {
  const byFamily = firstByFamily(checks, 'checkFamily', 'health_check_duplicate', reasons);

  for (const family of REQUIRED_HEALTH_CHECKS) {
    const check = byFamily.get(family);
    addReason(reasons, check === undefined, `missing_health_check:${family}`);
    if (check === undefined) {
      continue;
    }
    addReason(reasons, !HEALTH_CHECK_STATUSES.has(check.status), `health_check_not_passing:${family}`);
    addReason(reasons, !hasText(check.endpointRef), `health_check_endpoint_absent:${family}`);
    addReason(reasons, !isDigest(check.evidenceHash), `health_check_evidence_hash_invalid:${family}`);
    addReason(reasons, !hasText(check.checkedByDid), `health_check_checker_absent:${family}`);
    addReason(reasons, hlcTuple(check.checkedAtHlc) === null, `health_check_time_invalid:${family}`);
    addReason(reasons, check.metadataOnly !== true, `health_check_metadata_boundary_invalid:${family}`);
    addReason(reasons, check.protectedContentExcluded !== true, `health_check_protected_boundary_invalid:${family}`);
  }

  for (const family of byFamily.keys()) {
    addReason(reasons, !REQUIRED_HEALTH_CHECKS.includes(family), `unsupported_health_check:${family}`);
  }

  return REQUIRED_HEALTH_CHECKS.filter((family) => {
    const check = byFamily.get(family);
    return (
      check !== undefined &&
      HEALTH_CHECK_STATUSES.has(check.status) &&
      hasText(check.endpointRef) &&
      isDigest(check.evidenceHash) &&
      hasText(check.checkedByDid) &&
      hlcTuple(check.checkedAtHlc) !== null &&
      check.metadataOnly === true &&
      check.protectedContentExcluded === true
    );
  });
}

function evaluateObservabilitySignals(signals, reasons) {
  const byFamily = firstByFamily(signals, 'signalFamily', 'observability_signal_duplicate', reasons);

  for (const family of REQUIRED_OBSERVABILITY_SIGNALS) {
    const signal = byFamily.get(family);
    addReason(reasons, signal === undefined, `missing_observability_signal:${family}`);
    if (signal === undefined) {
      continue;
    }
    addReason(reasons, !OBSERVABILITY_SIGNAL_STATUSES.has(signal.status), `observability_signal_not_active:${family}`);
    addReason(reasons, !isDigest(signal.evidenceHash), `observability_signal_evidence_hash_invalid:${family}`);
    addReason(reasons, !isDigest(signal.alertRuleHash), `observability_signal_alert_rule_hash_invalid:${family}`);
    addReason(reasons, !isBasisPoints(signal.thresholdBasisPoints), `observability_signal_threshold_invalid:${family}`);
    addReason(reasons, !isBasisPoints(signal.observedBasisPoints), `observability_signal_observed_invalid:${family}`);
    addReason(
      reasons,
      isBasisPoints(signal.thresholdBasisPoints) &&
        isBasisPoints(signal.observedBasisPoints) &&
        signal.observedBasisPoints < signal.thresholdBasisPoints,
      `observability_signal_below_threshold:${family}`,
    );
    addReason(reasons, hlcTuple(signal.evaluatedAtHlc) === null, `observability_signal_time_invalid:${family}`);
    addReason(reasons, signal.metadataOnly !== true, `observability_signal_metadata_boundary_invalid:${family}`);
    addReason(reasons, signal.protectedContentExcluded !== true, `observability_signal_protected_boundary_invalid:${family}`);
  }

  for (const family of byFamily.keys()) {
    addReason(reasons, !REQUIRED_OBSERVABILITY_SIGNALS.includes(family), `unsupported_observability_signal:${family}`);
  }

  return REQUIRED_OBSERVABILITY_SIGNALS.filter((family) => {
    const signal = byFamily.get(family);
    return (
      signal !== undefined &&
      OBSERVABILITY_SIGNAL_STATUSES.has(signal.status) &&
      isDigest(signal.evidenceHash) &&
      isDigest(signal.alertRuleHash) &&
      isBasisPoints(signal.thresholdBasisPoints) &&
      isBasisPoints(signal.observedBasisPoints) &&
      signal.observedBasisPoints >= signal.thresholdBasisPoints &&
      hlcTuple(signal.evaluatedAtHlc) !== null &&
      signal.metadataOnly === true &&
      signal.protectedContentExcluded === true
    );
  });
}

function evaluateTelemetryBoundaries(boundaries, reasons) {
  const byFamily = firstByFamily(boundaries, 'boundaryFamily', 'telemetry_boundary_duplicate', reasons);

  for (const family of REQUIRED_TELEMETRY_BOUNDARIES) {
    const boundary = byFamily.get(family);
    addReason(reasons, boundary === undefined, `missing_telemetry_boundary:${family}`);
    if (boundary === undefined) {
      continue;
    }
    addReason(reasons, !TELEMETRY_BOUNDARY_STATUSES.has(boundary.status), `telemetry_boundary_not_verified:${family}`);
    addReason(reasons, !isDigest(boundary.evidenceHash), `telemetry_boundary_evidence_hash_invalid:${family}`);
    addReason(reasons, boundary.payloadsRedacted !== true, `telemetry_boundary_payload_redaction_absent:${family}`);
    addReason(reasons, boundary.labelsMinimized !== true, `telemetry_boundary_label_minimization_absent:${family}`);
    addReason(reasons, boundary.secretsExcluded !== true, `telemetry_boundary_secret_exclusion_absent:${family}`);
    addReason(reasons, boundary.protectedContentExcluded !== true, `telemetry_boundary_protected_exclusion_absent:${family}`);
    addReason(reasons, hlcTuple(boundary.verifiedAtHlc) === null, `telemetry_boundary_time_invalid:${family}`);
    addReason(reasons, boundary.metadataOnly !== true, `telemetry_boundary_metadata_invalid:${family}`);
  }

  for (const family of byFamily.keys()) {
    addReason(reasons, !REQUIRED_TELEMETRY_BOUNDARIES.includes(family), `unsupported_telemetry_boundary:${family}`);
  }

  return REQUIRED_TELEMETRY_BOUNDARIES.filter((family) => {
    const boundary = byFamily.get(family);
    return (
      boundary !== undefined &&
      TELEMETRY_BOUNDARY_STATUSES.has(boundary.status) &&
      isDigest(boundary.evidenceHash) &&
      boundary.payloadsRedacted === true &&
      boundary.labelsMinimized === true &&
      boundary.secretsExcluded === true &&
      boundary.protectedContentExcluded === true &&
      hlcTuple(boundary.verifiedAtHlc) !== null &&
      boundary.metadataOnly === true
    );
  });
}

function evaluateIncidentRunbooks(runbooks, reasons) {
  const byFamily = firstByFamily(runbooks, 'runbookFamily', 'incident_runbook_duplicate', reasons);

  for (const family of REQUIRED_INCIDENT_RUNBOOKS) {
    const runbook = byFamily.get(family);
    addReason(reasons, runbook === undefined, `missing_incident_runbook:${family}`);
    if (runbook === undefined) {
      continue;
    }
    addReason(reasons, !hasText(runbook.runbookRef), `incident_runbook_ref_absent:${family}`);
    addReason(reasons, !INCIDENT_RUNBOOK_STATUSES.has(runbook.status), `incident_runbook_not_approved:${family}`);
    addReason(reasons, !isDigest(runbook.runbookHash), `incident_runbook_hash_invalid:${family}`);
    addReason(reasons, !hasText(runbook.ownerDid), `incident_runbook_owner_absent:${family}`);
    addReason(reasons, !hasText(runbook.backupOwnerDid), `incident_runbook_backup_owner_absent:${family}`);
    addReason(reasons, !isDigest(runbook.escalationRouteHash), `incident_runbook_escalation_hash_invalid:${family}`);
    addReason(reasons, !isDigest(runbook.lastDrillEvidenceHash), `incident_runbook_drill_hash_invalid:${family}`);
    addReason(reasons, hlcTuple(runbook.reviewedAtHlc) === null, `incident_runbook_review_time_invalid:${family}`);
    addReason(reasons, runbook.metadataOnly !== true, `incident_runbook_metadata_boundary_invalid:${family}`);
    addReason(reasons, runbook.protectedContentExcluded !== true, `incident_runbook_protected_boundary_invalid:${family}`);
  }

  for (const family of byFamily.keys()) {
    addReason(reasons, !REQUIRED_INCIDENT_RUNBOOKS.includes(family), `unsupported_incident_runbook:${family}`);
  }

  return REQUIRED_INCIDENT_RUNBOOKS.filter((family) => {
    const runbook = byFamily.get(family);
    return (
      runbook !== undefined &&
      hasText(runbook.runbookRef) &&
      INCIDENT_RUNBOOK_STATUSES.has(runbook.status) &&
      isDigest(runbook.runbookHash) &&
      hasText(runbook.ownerDid) &&
      hasText(runbook.backupOwnerDid) &&
      isDigest(runbook.escalationRouteHash) &&
      isDigest(runbook.lastDrillEvidenceHash) &&
      hlcTuple(runbook.reviewedAtHlc) !== null &&
      runbook.metadataOnly === true &&
      runbook.protectedContentExcluded === true
    );
  });
}

function evaluateSloReview(sloReview, reasons) {
  addReason(reasons, !hasText(sloReview?.sloRef), 'slo_ref_absent');
  addReason(reasons, !isBasisPoints(sloReview?.uptimeTargetBasisPoints), 'uptime_target_invalid');
  addReason(reasons, !isBasisPoints(sloReview?.uptimeObservedBasisPoints), 'uptime_observed_invalid');
  addReason(reasons, !isBasisPoints(sloReview?.trustReadinessTargetBasisPoints), 'trust_readiness_target_invalid');
  addReason(reasons, !isBasisPoints(sloReview?.trustReadinessObservedBasisPoints), 'trust_readiness_observed_invalid');
  addReason(reasons, !isBasisPoints(sloReview?.errorBudgetRemainingBasisPoints), 'error_budget_remaining_invalid');
  addReason(
    reasons,
    isBasisPoints(sloReview?.uptimeTargetBasisPoints) &&
      isBasisPoints(sloReview?.uptimeObservedBasisPoints) &&
      sloReview.uptimeObservedBasisPoints < sloReview.uptimeTargetBasisPoints,
    'uptime_slo_breach',
  );
  addReason(
    reasons,
    isBasisPoints(sloReview?.trustReadinessTargetBasisPoints) &&
      isBasisPoints(sloReview?.trustReadinessObservedBasisPoints) &&
      sloReview.trustReadinessObservedBasisPoints < sloReview.trustReadinessTargetBasisPoints,
    'trust_readiness_slo_breach',
  );
  addReason(
    reasons,
    isBasisPoints(sloReview?.errorBudgetRemainingBasisPoints) &&
      sloReview.errorBudgetRemainingBasisPoints < ERROR_BUDGET_MINIMUM_BASIS_POINTS,
    'error_budget_exhausted',
  );
  addReason(reasons, !isDigest(sloReview?.reportHash), 'slo_report_hash_invalid');
  addReason(reasons, hlcTuple(sloReview?.reviewedAtHlc) === null, 'slo_review_time_invalid');
  addReason(reasons, sloReview?.metadataOnly !== true, 'slo_review_metadata_boundary_invalid');
}

function evaluateValidationEvidence(validation, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, !commandRefs.includes('npm test'), 'validation_npm_test_absent');
  addReason(reasons, !commandRefs.includes('npm run quality'), 'validation_quality_gate_absent');
  addReason(reasons, !commandRefs.includes('source guard'), 'validation_source_guard_command_absent');
  addReason(reasons, !commandRefs.includes('observability payload scan'), 'validation_observability_payload_scan_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, validation?.payloadScanPassed !== true, 'validation_payload_scan_not_passed');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_source_modified');
  addReason(reasons, !isDigest(validation?.testEvidenceHash), 'validation_test_evidence_hash_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_recommendation_without_human_review');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  for (const hash of Array.isArray(aiAssistance.limitationHashes) ? aiAssistance.limitationHashes : []) {
    addReason(reasons, !isDigest(hash), 'ai_limitation_hash_invalid');
  }
}

function latestObservabilityEvidenceHlc(input) {
  return latestHlc([
    ...(Array.isArray(input?.healthChecks) ? input.healthChecks.map((check) => check?.checkedAtHlc) : []),
    ...(Array.isArray(input?.observabilitySignals)
      ? input.observabilitySignals.map((signal) => signal?.evaluatedAtHlc)
      : []),
    ...(Array.isArray(input?.telemetryBoundaries)
      ? input.telemetryBoundaries.map((boundary) => boundary?.verifiedAtHlc)
      : []),
    ...(Array.isArray(input?.incidentRunbooks) ? input.incidentRunbooks.map((runbook) => runbook?.reviewedAtHlc) : []),
    input?.sloReview?.reviewedAtHlc,
  ]);
}

function evaluateHlcOrdering(input, reasons) {
  const latestEvidence = latestObservabilityEvidenceHlc(input);
  addReason(
    reasons,
    latestEvidence === null || !hlcAfter(input?.validationEvidence?.recordedAtHlc, latestEvidence),
    'validation_before_observability_evidence',
  );
  addReason(
    reasons,
    !hlcAfter(input?.humanReview?.reviewedAtHlc, input?.validationEvidence?.recordedAtHlc),
    'human_review_before_validation',
  );
}

function buildReadinessRecord({
  input,
  healthChecksCovered,
  observabilitySignalsCovered,
  telemetryBoundariesCovered,
  incidentRunbooksCovered,
  blockedBy,
}) {
  return {
    schema: HEALTH_OBSERVABILITY_SCHEMA,
    tenantId: input?.tenantId ?? null,
    serviceRef: input?.service?.serviceRef ?? null,
    releaseCandidateRef: input?.service?.releaseCandidateRef ?? null,
    healthChecksCovered: uniqueSorted(healthChecksCovered),
    observabilitySignalsCovered: uniqueSorted(observabilitySignalsCovered),
    telemetryBoundariesCovered: uniqueSorted(telemetryBoundariesCovered),
    incidentRunbooksCovered: uniqueSorted(incidentRunbooksCovered),
    healthCoverageBasisPoints: integerBasisPoints(healthChecksCovered.length, REQUIRED_HEALTH_CHECKS.length),
    observabilityCoverageBasisPoints: integerBasisPoints(
      observabilitySignalsCovered.length,
      REQUIRED_OBSERVABILITY_SIGNALS.length,
    ),
    telemetryBoundaryBasisPoints: integerBasisPoints(telemetryBoundariesCovered.length, REQUIRED_TELEMETRY_BOUNDARIES.length),
    incidentRunbookBasisPoints: integerBasisPoints(incidentRunbooksCovered.length, REQUIRED_INCIDENT_RUNBOOKS.length),
    slo: {
      uptimeObservedBasisPoints: Number.isSafeInteger(input?.sloReview?.uptimeObservedBasisPoints)
        ? input.sloReview.uptimeObservedBasisPoints
        : null,
      trustReadinessObservedBasisPoints: Number.isSafeInteger(input?.sloReview?.trustReadinessObservedBasisPoints)
        ? input.sloReview.trustReadinessObservedBasisPoints
        : null,
      errorBudgetRemainingBasisPoints: Number.isSafeInteger(input?.sloReview?.errorBudgetRemainingBasisPoints)
        ? input.sloReview.errorBudgetRemainingBasisPoints
        : null,
    },
    blockedBy: uniqueReasons(blockedBy),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, readinessHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'health_observability_readiness',
    artifactVersion: `${input.service.serviceRef}:${input.service.releaseCandidateRef}`,
    artifactHash: readinessHash,
    custodyDigest: input.custodyDigest,
    classification: 'health_observability_metadata_only',
    sensitivityTags: ['operations_metadata', 'health_metadata', 'observability_metadata'],
    sourceSystem: 'cybermedica.health_observability_readiness',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
  });
}

export function evaluateHealthObservabilityReadiness(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.observabilityPolicy, reasons);
  evaluateService(input?.service, reasons);
  const healthChecksCovered = evaluateHealthChecks(input?.healthChecks, reasons);
  const observabilitySignalsCovered = evaluateObservabilitySignals(input?.observabilitySignals, reasons);
  const telemetryBoundariesCovered = evaluateTelemetryBoundaries(input?.telemetryBoundaries, reasons);
  const incidentRunbooksCovered = evaluateIncidentRunbooks(input?.incidentRunbooks, reasons);
  evaluateSloReview(input?.sloReview, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  evaluateHlcOrdering(input, reasons);

  const blockedBy = uniqueReasons(reasons);
  const readinessRecord = buildReadinessRecord({
    input,
    healthChecksCovered,
    observabilitySignalsCovered,
    telemetryBoundariesCovered,
    incidentRunbooksCovered,
    blockedBy,
  });
  const readinessHash = sha256Hex(readinessRecord);
  const allowed = blockedBy.length === 0;

  return {
    schema: HEALTH_OBSERVABILITY_SCHEMA,
    allowed,
    state: allowed ? 'ready_inactive_trust' : 'denied',
    failClosed: !allowed,
    trustState: 'inactive',
    exochainProductionClaim: false,
    healthObservabilityReady: allowed,
    productionTrustReady: false,
    blockedBy,
    readinessHash,
    readiness: {
      ...readinessRecord,
      readinessHash,
    },
    receipt: allowed ? buildReceipt(input, readinessHash) : null,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#deployment-backlog',
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md#rt-003',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    ],
  };
}
