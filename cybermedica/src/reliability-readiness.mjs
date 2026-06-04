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
const RELIABILITY_READINESS_SCHEMA = 'cybermedica.reliability_readiness.v1';
const REQUIRED_PERMISSION = 'reliability_readiness_review';

const REQUIRED_FAILURE_SCENARIOS = Object.freeze([
  'duplicate_submission',
  'integration_failure',
  'interrupted_upload',
  'partial_failure',
  'retry_scenario',
]);

const REQUIRED_RECOVERY_CONTROLS = Object.freeze([
  'bounded_retry',
  'dead_letter_queue',
  'duplicate_submission_detector',
  'idempotency_key',
  'interrupted_upload_manifest',
  'reconciliation_job',
  'timeout_denial',
]);

const REQUIRED_DEPENDENCY_FAMILIES = Object.freeze([
  'decision_forum',
  'exochain_gateway',
  'exochain_node_receipts',
  'integration_connector',
  'object_storage',
  'operational_database',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const FAILURE_SCENARIO_STATUSES = new Set(['passed']);
const RECOVERY_CONTROL_STATUSES = new Set(['verified']);
const DEPENDENCY_RECOVERY_STATUSES = new Set(['verified']);
const DEPENDENCY_RESPONSE_MODES = new Set(['fail_closed', 'queue_and_reconcile']);
const HUMAN_REVIEW_DECISIONS = new Set(['accepted_inactive_trust']);
const PARTIAL_FAILURE_MODES = new Set(['fail_closed']);
const INTEGRATION_FAILURE_MODES = new Set(['fail_closed', 'queue_and_reconcile']);
const INTERRUPTED_UPLOAD_MODES = new Set(['fail_closed', 'resume_from_manifest']);
const DUPLICATE_SUBMISSION_MODES = new Set(['idempotent_reject']);
const RETRY_MODES = new Set(['bounded_idempotent_retry']);
const RETRY_BACKOFF_STRATEGIES = new Set(['bounded_exponential', 'fixed_interval', 'manual_review_required']);

const RAW_RELIABILITY_FIELDS = new Set([
  'duplicatebody',
  'duplicatesubmissionbody',
  'errorbody',
  'errorpayload',
  'freetextnote',
  'integrationpayload',
  'participantlisting',
  'rawbody',
  'rawclinicaldata',
  'rawdependencyresponse',
  'rawerror',
  'rawfailurepayload',
  'rawintegrationpayload',
  'rawlog',
  'rawpayload',
  'rawretrylog',
  'rawsource',
  'rawsourcedocument',
  'rawtelemetry',
  'rawupload',
  'rawuploadchunk',
  'rawuploaddata',
  'retrylogbody',
  'sourcebody',
  'sourcedocumentbody',
  'uploaddatabody',
]);

const SECRET_RELIABILITY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
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

function assertNoRawReliabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawReliabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RELIABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw reliability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RELIABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`reliability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawReliabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawReliabilityContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  const values = sortedTextList(actual);
  for (const required of expected) {
    addReason(reasons, !values.includes(required), `${missingPrefix}:${required}`);
  }
  for (const value of values) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
  return values;
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
    'reliability_readiness_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateReliabilityPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'reliability_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'reliability_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'reliability_policy_not_active');
  addReason(reasons, !PARTIAL_FAILURE_MODES.has(policy?.partialFailureMode), 'partial_failure_mode_invalid');
  addReason(reasons, !INTEGRATION_FAILURE_MODES.has(policy?.integrationFailureMode), 'integration_failure_mode_invalid');
  addReason(reasons, !INTERRUPTED_UPLOAD_MODES.has(policy?.interruptedUploadMode), 'interrupted_upload_mode_invalid');
  addReason(reasons, !DUPLICATE_SUBMISSION_MODES.has(policy?.duplicateSubmissionMode), 'duplicate_submission_mode_invalid');
  addReason(reasons, !RETRY_MODES.has(policy?.retryMode), 'retry_mode_invalid');
  addReason(reasons, !RETRY_BACKOFF_STRATEGIES.has(policy?.retryBackoffStrategy), 'retry_backoff_strategy_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(policy?.maxRetryCount) || policy.maxRetryCount <= 0 || policy.maxRetryCount > 25,
    'retry_count_invalid',
  );
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'reliability_policy_time_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'reliability_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'reliability_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  evaluateRequiredSet(
    policy?.requiredFailureScenarios,
    REQUIRED_FAILURE_SCENARIOS,
    'policy_failure_scenario_missing',
    'policy_failure_scenario_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    policy?.requiredRecoveryControls,
    REQUIRED_RECOVERY_CONTROLS,
    'policy_recovery_control_missing',
    'policy_recovery_control_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    policy?.requiredDependencyFamilies,
    REQUIRED_DEPENDENCY_FAMILIES,
    'policy_dependency_family_missing',
    'policy_dependency_family_unsupported',
    reasons,
  );
}

function evaluateService(service, reasons) {
  addReason(reasons, !hasText(service?.serviceRef), 'service_ref_absent');
  addReason(reasons, !hasText(service?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, !hasText(service?.ownerDid), 'service_owner_absent');
  addReason(reasons, !hasText(service?.backupOwnerDid), 'service_backup_owner_absent');
  addReason(reasons, !isDigest(service?.runtimeTopologyHash), 'runtime_topology_hash_invalid');
  addReason(reasons, !isDigest(service?.idempotencyKeyFormatHash), 'idempotency_key_format_hash_invalid');
  addReason(reasons, !isDigest(service?.retryPolicyHash), 'retry_policy_hash_invalid');
  addReason(reasons, !isDigest(service?.reconciliationPolicyHash), 'reconciliation_policy_hash_invalid');
  addReason(reasons, !isDigest(service?.queuePolicyHash), 'queue_policy_hash_invalid');
  addReason(reasons, !isDigest(service?.uploadManifestPolicyHash), 'upload_manifest_policy_hash_invalid');
  addReason(reasons, service?.metadataOnly !== true, 'service_metadata_boundary_invalid');
  addReason(reasons, service?.sourcePayloadsRemainExternal !== true, 'service_source_payload_boundary_invalid');
  addReason(reasons, service?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizeFailureScenarios(input, reasons) {
  const scenarios = Array.isArray(input?.failureScenarios) ? input.failureScenarios : [];
  addReason(reasons, scenarios.length === 0, 'failure_scenarios_absent');

  const byScenario = new Map();
  for (const item of scenarios) {
    if (hasText(item?.scenario)) {
      addReason(reasons, byScenario.has(item.scenario), `failure_scenario_duplicate:${item.scenario}`);
      byScenario.set(item.scenario, item);
    }
    if (hasText(item?.scenario) && !REQUIRED_FAILURE_SCENARIOS.includes(item.scenario)) {
      reasons.push(`failure_scenario_unsupported:${item.scenario}`);
    }
  }

  const normalized = [];
  for (const scenario of REQUIRED_FAILURE_SCENARIOS) {
    const item = byScenario.get(scenario);
    if (item === undefined) {
      reasons.push(`failure_scenario_missing:${scenario}`);
      continue;
    }

    const evidenceRef = hasText(item?.evidenceRef) ? item.evidenceRef : `failure_scenario_${scenario}`;
    addReason(reasons, !FAILURE_SCENARIO_STATUSES.has(item?.status), `failure_scenario_not_passed:${scenario}`);
    addReason(reasons, !hasText(item?.evidenceRef), `failure_scenario_evidence_ref_absent:${scenario}`);
    addReason(reasons, !isDigest(item?.evidenceHash), `failure_scenario_evidence_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(item?.recoveryArtifactHash), `failure_scenario_recovery_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(item?.reconciliationEvidenceHash), `failure_scenario_reconciliation_hash_invalid:${evidenceRef}`);
    addReason(reasons, hlcTuple(item?.exercisedAtHlc) === null, `failure_scenario_time_invalid:${evidenceRef}`);
    addReason(
      reasons,
      hlcBefore(item?.exercisedAtHlc, input?.reliabilityPolicy?.evaluatedAtHlc),
      `failure_scenario_before_policy_evaluation:${evidenceRef}`,
    );
    addReason(reasons, item?.failClosedObserved !== true, `failure_scenario_fail_closed_absent:${scenario}`);
    addReason(reasons, item?.idempotencyPreserved !== true, `failure_scenario_idempotency_absent:${scenario}`);
    addReason(reasons, item?.noPayloadDisclosure !== true, `failure_scenario_payload_boundary_invalid:${scenario}`);
    addReason(reasons, item?.metadataOnly !== true, `failure_scenario_metadata_boundary_invalid:${scenario}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `failure_scenario_protected_boundary_invalid:${scenario}`);

    normalized.push({
      evidenceHash: item?.evidenceHash ?? null,
      evidenceRef,
      exercisedAtHlc: item?.exercisedAtHlc ?? null,
      recoveryArtifactHash: item?.recoveryArtifactHash ?? null,
      reconciliationEvidenceHash: item?.reconciliationEvidenceHash ?? null,
      scenario,
    });
  }

  return normalized.sort((left, right) => left.scenario.localeCompare(right.scenario));
}

function normalizeRecoveryControls(input, reasons) {
  const controls = Array.isArray(input?.recoveryControls) ? input.recoveryControls : [];
  addReason(reasons, controls.length === 0, 'recovery_controls_absent');

  const byControl = new Map();
  for (const item of controls) {
    if (hasText(item?.controlFamily)) {
      addReason(reasons, byControl.has(item.controlFamily), `recovery_control_duplicate:${item.controlFamily}`);
      byControl.set(item.controlFamily, item);
    }
    if (hasText(item?.controlFamily) && !REQUIRED_RECOVERY_CONTROLS.includes(item.controlFamily)) {
      reasons.push(`recovery_control_unsupported:${item.controlFamily}`);
    }
  }

  const normalized = [];
  for (const controlFamily of REQUIRED_RECOVERY_CONTROLS) {
    const item = byControl.get(controlFamily);
    if (item === undefined) {
      reasons.push(`recovery_control_missing:${controlFamily}`);
      continue;
    }

    addReason(reasons, !RECOVERY_CONTROL_STATUSES.has(item?.status), `recovery_control_not_verified:${controlFamily}`);
    addReason(reasons, !isDigest(item?.evidenceHash), `recovery_control_evidence_hash_invalid:${controlFamily}`);
    addReason(reasons, !hasText(item?.ownerDid), `recovery_control_owner_absent:${controlFamily}`);
    addReason(reasons, hlcTuple(item?.verifiedAtHlc) === null, `recovery_control_time_invalid:${controlFamily}`);
    addReason(
      reasons,
      hlcBefore(item?.verifiedAtHlc, input?.reliabilityPolicy?.evaluatedAtHlc),
      `recovery_control_before_policy_evaluation:${controlFamily}`,
    );
    addReason(reasons, item?.metadataOnly !== true, `recovery_control_metadata_boundary_invalid:${controlFamily}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `recovery_control_protected_boundary_invalid:${controlFamily}`);

    normalized.push({
      controlFamily,
      evidenceHash: item?.evidenceHash ?? null,
      verifiedAtHlc: item?.verifiedAtHlc ?? null,
    });
  }

  return normalized.sort((left, right) => left.controlFamily.localeCompare(right.controlFamily));
}

function normalizeDependencyRecoveries(input, reasons) {
  const recoveries = Array.isArray(input?.dependencyRecoveries) ? input.dependencyRecoveries : [];
  addReason(reasons, recoveries.length === 0, 'dependency_recoveries_absent');

  const byDependency = new Map();
  for (const item of recoveries) {
    if (hasText(item?.dependencyFamily)) {
      addReason(reasons, byDependency.has(item.dependencyFamily), `dependency_recovery_duplicate:${item.dependencyFamily}`);
      byDependency.set(item.dependencyFamily, item);
    }
    if (hasText(item?.dependencyFamily) && !REQUIRED_DEPENDENCY_FAMILIES.includes(item.dependencyFamily)) {
      reasons.push(`dependency_recovery_unsupported:${item.dependencyFamily}`);
    }
  }

  const normalized = [];
  for (const dependencyFamily of REQUIRED_DEPENDENCY_FAMILIES) {
    const item = byDependency.get(dependencyFamily);
    if (item === undefined) {
      reasons.push(`dependency_recovery_missing:${dependencyFamily}`);
      continue;
    }

    addReason(reasons, !DEPENDENCY_RECOVERY_STATUSES.has(item?.status), `dependency_recovery_not_verified:${dependencyFamily}`);
    addReason(reasons, !DEPENDENCY_RESPONSE_MODES.has(item?.responseMode), `dependency_response_mode_invalid:${dependencyFamily}`);
    addReason(reasons, !isDigest(item?.evidenceHash), `dependency_recovery_evidence_hash_invalid:${dependencyFamily}`);
    addReason(reasons, hlcTuple(item?.checkedAtHlc) === null, `dependency_check_time_invalid:${dependencyFamily}`);
    addReason(
      reasons,
      hlcBefore(item?.checkedAtHlc, input?.reliabilityPolicy?.evaluatedAtHlc),
      `dependency_checked_before_policy_evaluation:${dependencyFamily}`,
    );
    addReason(reasons, item?.timeoutDenied !== true, `dependency_timeout_denial_absent:${dependencyFamily}`);
    addReason(reasons, item?.staleResponseRejected !== true, `dependency_stale_response_denial_absent:${dependencyFamily}`);
    addReason(reasons, item?.retryBounded !== true, `dependency_retry_boundary_absent:${dependencyFamily}`);
    addReason(reasons, item?.trustOutcomeNotOverridden !== true, `dependency_trust_override_forbidden:${dependencyFamily}`);
    addReason(reasons, item?.metadataOnly !== true, `dependency_recovery_metadata_boundary_invalid:${dependencyFamily}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `dependency_recovery_protected_boundary_invalid:${dependencyFamily}`);

    normalized.push({
      checkedAtHlc: item?.checkedAtHlc ?? null,
      dependencyFamily,
      evidenceHash: item?.evidenceHash ?? null,
      responseMode: item?.responseMode ?? null,
    });
  }

  return normalized.sort((left, right) => left.dependencyFamily.localeCompare(right.dependencyFamily));
}

function evaluateOperationsReview(review, failureScenarios, recoveryControls, dependencyRecoveries, reasons) {
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'operations_review_not_accepted');
  addReason(reasons, !hasText(review?.reviewedByDid), 'operations_reviewer_absent');
  addReason(reasons, !isDigest(review?.reviewHash), 'operations_review_hash_invalid');
  addReason(reasons, review?.materialIncidentOpen === true, 'material_reliability_incident_open');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'operations_review_time_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'operations_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'operations_review_protected_boundary_invalid');

  for (const scenario of failureScenarios) {
    addReason(
      reasons,
      hlcAfter(scenario.exercisedAtHlc, review?.reviewedAtHlc),
      `operations_review_before_failure_scenario:${scenario.scenario}`,
    );
  }
  for (const control of recoveryControls) {
    addReason(
      reasons,
      hlcAfter(control.verifiedAtHlc, review?.reviewedAtHlc),
      `operations_review_before_recovery_control:${control.controlFamily}`,
    );
  }
  for (const dependency of dependencyRecoveries) {
    addReason(
      reasons,
      hlcAfter(dependency.checkedAtHlc, review?.reviewedAtHlc),
      `operations_review_before_dependency_check:${dependency.dependencyFamily}`,
    );
  }
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance?.used !== true) {
    return false;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance?.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance?.scopeHash), 'ai_scope_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance?.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  for (const hash of Array.isArray(aiAssistance?.limitationHashes) ? aiAssistance.limitationHashes : []) {
    addReason(reasons, !isDigest(hash), 'ai_limitation_hash_invalid');
  }
  return true;
}

function buildReliabilityReadiness(input, failureScenarios, recoveryControls, dependencyRecoveries, aiAssisted, denied) {
  const failureScenarioFamilies = failureScenarios.map((item) => item.scenario).sort();
  const recoveryControlFamilies = recoveryControls.map((item) => item.controlFamily).sort();
  const dependencyFamilies = dependencyRecoveries.map((item) => item.dependencyFamily).sort();
  const readinessHash = sha256Hex({
    actorDid: input?.actor?.did ?? null,
    dependencyFamilies,
    failureScenarioFamilies,
    maxRetryCount: input?.reliabilityPolicy?.maxRetryCount ?? null,
    policyHash: input?.reliabilityPolicy?.policyHash ?? null,
    policyRef: input?.reliabilityPolicy?.policyRef ?? null,
    recoveryControlFamilies,
    releaseCandidateRef: input?.service?.releaseCandidateRef ?? null,
    reviewHash: input?.operationsReview?.reviewHash ?? null,
    schema: RELIABILITY_READINESS_SCHEMA,
    serviceRef: input?.service?.serviceRef ?? null,
    tenantId: input?.tenantId ?? null,
  });

  return {
    schema: RELIABILITY_READINESS_SCHEMA,
    nfrId: 'NFR-012',
    readinessId: `cm_rel_${readinessHash.slice(0, 32)}`,
    readinessHash,
    ready: !denied,
    serviceRef: input?.service?.serviceRef ?? null,
    releaseCandidateRef: input?.service?.releaseCandidateRef ?? null,
    failureScenarios: failureScenarioFamilies,
    recoveryControls: recoveryControlFamilies,
    dependencyFamilies,
    maxRetryCount: Number.isSafeInteger(input?.reliabilityPolicy?.maxRetryCount)
      ? input.reliabilityPolicy.maxRetryCount
      : null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    sourcePayloadsStayExternal: input?.service?.sourcePayloadsRemainExternal === true,
    aiAssisted,
  };
}

function buildReceipt(input, reliabilityReadiness) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'reliability_readiness',
    artifactVersion: input.service.releaseCandidateRef,
    artifactHash: reliabilityReadiness.readinessHash,
    custodyDigest: input.custodyDigest,
    classification: 'qms_reliability_metadata',
    sensitivityTags: ['metadata_only', 'nfr_012', 'reliability_readiness'],
    sourceSystem: 'cybermedica-qms-contracts',
    hlcTimestamp: input.operationsReview.reviewedAtHlc,
  });
}

export function evaluateReliabilityReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReliabilityPolicy(input?.reliabilityPolicy, reasons);
  evaluateService(input?.service, reasons);

  const failureScenarios = normalizeFailureScenarios(input, reasons);
  const recoveryControls = normalizeRecoveryControls(input, reasons);
  const dependencyRecoveries = normalizeDependencyRecoveries(input, reasons);
  evaluateOperationsReview(input?.operationsReview, failureScenarios, recoveryControls, dependencyRecoveries, reasons);
  const aiAssisted = evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const denied = unique.length > 0;
  const reliabilityReadiness = buildReliabilityReadiness(
    input,
    failureScenarios,
    recoveryControls,
    dependencyRecoveries,
    aiAssisted,
    denied,
  );

  return {
    schema: 'cybermedica.reliability_readiness_decision.v1',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: unique,
    reliabilityReadiness,
    receipt: denied ? null : buildReceipt(input, reliabilityReadiness),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
