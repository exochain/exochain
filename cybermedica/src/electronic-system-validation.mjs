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
const ELECTRONIC_SYSTEM_VALIDATION_SCHEMA = 'cybermedica.electronic_system_validation.v1';
const REQUIRED_PERMISSION = 'system_validation';

const SYSTEM_TYPES = new Set([
  'ctms',
  'data_capture_device',
  'edc',
  'econsent',
  'eisf',
  'etmf',
  'lab_interface',
  'qms',
  'source_capture',
  'wearable',
]);

const REQUIRED_VALIDATION_TYPES = Object.freeze([
  'audit_trail',
  'backup_restore',
  'data_integrity',
  'electronic_signature',
  'installation_qualification',
  'integration_boundary',
  'operational_qualification',
  'performance_qualification',
  'security_access',
  'user_acceptance',
]);

const REQUIRED_RELIABILITY_SCENARIOS = Object.freeze([
  'duplicate_submission',
  'integration_failure',
  'interrupted_upload',
  'partial_failure',
  'retry_scenario',
]);

const REQUIRED_AUDIT_EVENT_FAMILIES = Object.freeze([
  'access',
  'approval',
  'authentication',
  'delegation',
  'decision',
  'document_change',
  'evidence',
  'export',
  'privileged_action',
]);

const VALIDATION_RESULTS = new Set(['passed']);
const RELIABILITY_STATUSES = new Set(['verified']);
const PARTIAL_FAILURE_MODES = new Set(['fail_closed']);
const INTEGRATION_FAILURE_MODES = new Set(['queue_and_reconcile', 'fail_closed']);
const INTERRUPTED_UPLOAD_MODES = new Set(['resume_from_manifest', 'fail_closed']);
const DUPLICATE_SUBMISSION_MODES = new Set(['idempotent_reject']);
const RETRY_MODES = new Set(['bounded_idempotent_retry']);
const RETRY_BACKOFF_STRATEGIES = new Set(['bounded_exponential', 'fixed_interval', 'manual_review_required']);

const RAW_SYSTEM_VALIDATION_FIELDS = new Set([
  'directidentifierlist',
  'ecrfbody',
  'freetextnote',
  'participantlisting',
  'rawaudittrail',
  'rawclinicaldata',
  'rawdata',
  'rawsource',
  'rawsourcedata',
  'rawsourcedocument',
  'rawtelemetry',
  'rawtrialdata',
  'rawuploaddata',
  'rawvalidationdata',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'trialdatabody',
  'validationnarrative',
]);

const SECRET_SYSTEM_VALIDATION_FIELDS = new Set([
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

function assertNoRawSystemValidationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSystemValidationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SYSTEM_VALIDATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw electronic system validation content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SYSTEM_VALIDATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`electronic system validation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSystemValidationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSystemValidationContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
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
    'system_validation_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSystem(system, reasons) {
  addReason(reasons, !hasText(system?.systemRef), 'system_ref_absent');
  addReason(reasons, !SYSTEM_TYPES.has(system?.systemType), 'system_type_invalid');
  addReason(reasons, !isDigest(system?.systemNameHash), 'system_name_hash_invalid');
  addReason(reasons, !hasText(system?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(system?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(system?.ownerDid), 'system_owner_absent');
  addReason(reasons, !hasText(system?.versionRef), 'system_version_ref_absent');
  addReason(reasons, !isDigest(system?.intendedUseHash), 'system_intended_use_hash_invalid');
  addReason(reasons, !isDigest(system?.configurationHash), 'system_configuration_hash_invalid');
  addReason(reasons, !isDigest(system?.dataFlowHash), 'system_data_flow_hash_invalid');
  addReason(reasons, !isDigest(system?.riskAssessmentHash), 'system_risk_assessment_hash_invalid');
  addReason(reasons, !isDigest(system?.accessPolicyHash), 'system_access_policy_hash_invalid');
  addReason(reasons, !isDigest(system?.auditTrailPolicyHash), 'system_audit_trail_policy_hash_invalid');
  addReason(reasons, !isDigest(system?.backupRecoveryHash), 'system_backup_recovery_hash_invalid');
  addReason(reasons, !isDigest(system?.changeControlHash), 'system_change_control_hash_invalid');
  addReason(reasons, !isDigest(system?.vendorQualificationHash), 'system_vendor_qualification_hash_invalid');
  addReason(reasons, !isDigest(system?.cybersecurityHash), 'system_cybersecurity_hash_invalid');
  addReason(reasons, system?.dataCollectionUse !== true, 'trial_data_collection_use_absent');
  addReason(reasons, system?.metadataOnly !== true, 'system_metadata_boundary_invalid');
  addReason(reasons, system?.sourcePayloadsRemainExternal !== true, 'system_source_payload_boundary_invalid');
  addReason(reasons, system?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateValidationPlan(plan, reasons) {
  const requiredTypes = sortedTextList(plan?.requiredEvidenceTypes);
  addReason(reasons, !hasText(plan?.planRef), 'validation_plan_ref_absent');
  addReason(reasons, !hasText(plan?.planVersion), 'validation_plan_version_absent');
  addReason(reasons, plan?.approved !== true, 'validation_plan_not_approved');
  addReason(reasons, !hasText(plan?.approvedByDid), 'validation_plan_approver_absent');
  addReason(reasons, !isDigest(plan?.approvalHash), 'validation_plan_approval_hash_invalid');
  addReason(reasons, hlcTuple(plan?.approvedAtHlc) === null, 'validation_plan_approval_time_invalid');
  addReason(reasons, !isDigest(plan?.acceptanceCriteriaHash), 'validation_acceptance_criteria_hash_invalid');
  addReason(reasons, !isDigest(plan?.traceabilityMatrixHash), 'validation_traceability_matrix_hash_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'validation_plan_metadata_boundary_invalid');

  for (const type of REQUIRED_VALIDATION_TYPES) {
    addReason(reasons, !requiredTypes.includes(type), `validation_plan_type_missing:${type}`);
  }

  return requiredTypes;
}

function normalizeValidationEvidence(input, reasons) {
  const evidence = Array.isArray(input?.validationEvidence) ? input.validationEvidence : [];
  addReason(reasons, evidence.length === 0, 'validation_evidence_absent');

  const byType = new Map();
  for (const item of evidence) {
    if (hasText(item?.evidenceType)) {
      addReason(reasons, byType.has(item.evidenceType), `validation_evidence_duplicate:${item.evidenceType}`);
      byType.set(item.evidenceType, item);
    }
  }

  const normalized = [];
  for (const type of REQUIRED_VALIDATION_TYPES) {
    const item = byType.get(type);
    if (item === undefined) {
      reasons.push(`validation_evidence_missing:${type}`);
      continue;
    }

    const evidenceRef = hasText(item?.evidenceRef) ? item.evidenceRef : 'unknown';
    addReason(reasons, !hasText(item?.evidenceRef), `validation_evidence_ref_absent:${type}`);
    addReason(reasons, !isDigest(item?.artifactHash), `validation_artifact_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(item?.verificationHash), `validation_verification_hash_invalid:${evidenceRef}`);
    addReason(reasons, !VALIDATION_RESULTS.has(item?.result), `validation_result_not_passed:${evidenceRef}`);
    addReason(reasons, !hasText(item?.executedByDid), `validation_executor_absent:${evidenceRef}`);
    addReason(reasons, !hasText(item?.reviewedByDid), `validation_reviewer_absent:${evidenceRef}`);
    addReason(reasons, hlcTuple(item?.executedAtHlc) === null, `validation_execution_time_invalid:${evidenceRef}`);
    addReason(reasons, hlcTuple(item?.reviewedAtHlc) === null, `validation_review_time_invalid:${evidenceRef}`);
    addReason(
      reasons,
      hlcBeforeOrEqual(item?.reviewedAtHlc, item?.executedAtHlc),
      `validation_review_not_after_execution:${evidenceRef}`,
    );
    addReason(
      reasons,
      hlcBefore(item?.executedAtHlc, input?.validationPlan?.approvedAtHlc),
      `validation_executed_before_plan_approval:${evidenceRef}`,
    );
    addReason(reasons, item?.metadataOnly !== true, `validation_metadata_boundary_invalid:${evidenceRef}`);
    addReason(reasons, item?.rawTrialDataExcluded !== true, `validation_raw_trial_data_boundary_invalid:${evidenceRef}`);
    addReason(reasons, item?.protectedPayloadExcluded !== true, `validation_protected_payload_boundary_invalid:${evidenceRef}`);

    normalized.push({
      artifactHash: item?.artifactHash ?? null,
      evidenceRef,
      evidenceType: type,
      reviewedAtHlc: item?.reviewedAtHlc ?? null,
      verificationHash: item?.verificationHash ?? null,
    });
  }

  return normalized.sort((left, right) => left.evidenceType.localeCompare(right.evidenceType));
}

function evaluateRelease(input, validationEvidence, reasons) {
  const release = input?.release;
  addReason(reasons, !hasText(release?.releaseRef), 'release_ref_absent');
  addReason(reasons, !isDigest(release?.releaseHash), 'release_hash_invalid');
  addReason(reasons, !hasText(release?.releasedByDid), 'release_actor_absent');
  addReason(reasons, release?.humanApproved !== true, 'release_human_approval_absent');
  addReason(reasons, !Number.isSafeInteger(release?.openCriticalDefectCount) || release.openCriticalDefectCount < 0, 'release_critical_defect_count_invalid');
  addReason(reasons, !Number.isSafeInteger(release?.openMajorDefectCount) || release.openMajorDefectCount < 0, 'release_major_defect_count_invalid');
  addReason(reasons, release?.openCriticalDefectCount > 0, 'release_critical_defects_open');
  addReason(reasons, release?.openMajorDefectCount > 0, 'release_major_defects_open');
  addReason(reasons, sortedTextList(release?.unresolvedDeviationRefs).length > 0, 'release_unresolved_deviations_open');
  addReason(reasons, !isDigest(release?.trainingCommunicationHash), 'release_training_communication_hash_invalid');
  addReason(reasons, !isDigest(release?.goLiveChecklistHash), 'release_go_live_checklist_hash_invalid');
  addReason(reasons, hlcTuple(release?.validatedAtHlc) === null, 'release_validated_time_invalid');
  addReason(reasons, hlcTuple(release?.releasedAtHlc) === null, 'release_time_invalid');
  addReason(reasons, hlcBeforeOrEqual(release?.releasedAtHlc, release?.validatedAtHlc), 'release_before_validation');
  addReason(
    reasons,
    hlcBefore(release?.validatedAtHlc, input?.reliabilityPlan?.evaluatedAtHlc),
    'release_validation_before_reliability_evaluation',
  );

  for (const item of validationEvidence) {
    addReason(
      reasons,
      hlcAfter(item.reviewedAtHlc, release?.validatedAtHlc),
      `release_validation_before_evidence_review:${item.evidenceRef}`,
    );
  }
}

function evaluateReliabilityPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'reliability_plan_ref_absent');
  addReason(reasons, !RELIABILITY_STATUSES.has(plan?.status), 'reliability_plan_not_verified');
  addReason(reasons, !isDigest(plan?.planHash), 'reliability_plan_hash_invalid');
  addReason(reasons, hlcTuple(plan?.evaluatedAtHlc) === null, 'reliability_plan_time_invalid');
  addReason(reasons, !PARTIAL_FAILURE_MODES.has(plan?.partialFailureMode), 'partial_failure_mode_invalid');
  addReason(reasons, !INTEGRATION_FAILURE_MODES.has(plan?.integrationFailureMode), 'integration_failure_mode_invalid');
  addReason(reasons, !INTERRUPTED_UPLOAD_MODES.has(plan?.interruptedUploadMode), 'interrupted_upload_mode_invalid');
  addReason(reasons, !DUPLICATE_SUBMISSION_MODES.has(plan?.duplicateSubmissionMode), 'duplicate_submission_mode_invalid');
  addReason(reasons, !RETRY_MODES.has(plan?.retryMode), 'retry_mode_invalid');
  addReason(reasons, plan?.idempotencyKeyRequired !== true, 'idempotency_key_absent');
  addReason(reasons, plan?.duplicateSubmissionDetection !== true, 'duplicate_submission_detection_absent');
  addReason(reasons, plan?.interruptedUploadRecovery !== true, 'interrupted_upload_recovery_absent');
  addReason(reasons, !RETRY_BACKOFF_STRATEGIES.has(plan?.retryBackoffStrategy), 'retry_backoff_strategy_invalid');
  addReason(reasons, !Number.isSafeInteger(plan?.maxRetryCount) || plan.maxRetryCount <= 0 || plan.maxRetryCount > 25, 'retry_count_invalid');
  addReason(reasons, plan?.deadLetterQueueEnabled !== true, 'dead_letter_queue_absent');
  addReason(reasons, plan?.reconciliationRequired !== true, 'reconciliation_required_absent');
  addReason(reasons, !isDigest(plan?.monitoringEvidenceHash), 'reliability_monitoring_evidence_hash_invalid');
}

function normalizeReliabilityScenarios(input, reasons) {
  const scenarios = Array.isArray(input?.reliabilityScenarios) ? input.reliabilityScenarios : [];
  addReason(reasons, scenarios.length === 0, 'reliability_scenarios_absent');

  const byScenario = new Map();
  for (const item of scenarios) {
    if (hasText(item?.scenario)) {
      addReason(reasons, byScenario.has(item.scenario), `reliability_scenario_duplicate:${item.scenario}`);
      byScenario.set(item.scenario, item);
    }
  }

  const normalized = [];
  for (const scenario of REQUIRED_RELIABILITY_SCENARIOS) {
    const item = byScenario.get(scenario);
    if (item === undefined) {
      reasons.push(`reliability_scenario_missing:${scenario}`);
      continue;
    }

    const evidenceRef = hasText(item?.evidenceRef) ? item.evidenceRef : 'unknown';
    addReason(reasons, !hasText(item?.evidenceRef), `reliability_evidence_ref_absent:${scenario}`);
    addReason(reasons, !isDigest(item?.evidenceHash), `reliability_evidence_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(item?.reconciliationEvidenceHash), `reliability_reconciliation_hash_invalid:${evidenceRef}`);
    addReason(reasons, hlcTuple(item?.exercisedAtHlc) === null, `reliability_scenario_time_invalid:${evidenceRef}`);
    addReason(reasons, hlcBefore(item?.exercisedAtHlc, input?.validationPlan?.approvedAtHlc), `reliability_scenario_before_plan_approval:${evidenceRef}`);
    addReason(reasons, item?.passed !== true, `reliability_scenario_not_passed:${scenario}`);
    addReason(reasons, item?.failClosedObserved !== true, `reliability_scenario_fail_closed_absent:${scenario}`);

    normalized.push({
      evidenceHash: item?.evidenceHash ?? null,
      evidenceRef,
      reconciliationEvidenceHash: item?.reconciliationEvidenceHash ?? null,
      scenario,
    });
  }

  return normalized.sort((left, right) => left.scenario.localeCompare(right.scenario));
}

function evaluateIntegrationReadiness(readiness, reasons) {
  addReason(reasons, typeof readiness?.required !== 'boolean', 'integration_readiness_requirement_invalid');
  addReason(reasons, readiness?.rawPayloadLoggingDisabled !== true, 'integration_raw_payload_logging_forbidden');

  if (readiness?.required !== true) {
    addReason(reasons, readiness?.status !== 'not_applicable', 'integration_readiness_status_invalid');
    return;
  }

  addReason(reasons, !hasText(readiness?.readinessRef), 'integration_readiness_ref_absent');
  addReason(reasons, readiness?.status !== 'ready', 'integration_readiness_not_ready');
  addReason(reasons, !isDigest(readiness?.readinessHash), 'integration_readiness_hash_invalid');
  addReason(reasons, readiness?.governedApiOnly !== true, 'integration_governed_api_only_absent');
  addReason(reasons, readiness?.webhookSignatureRequired !== true, 'integration_webhook_signature_absent');
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, boundary?.phiPiiExcludedFromReceipts !== true, 'privacy_phi_pii_receipt_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.payloadsRemainInSourceSystems !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.sourceDocumentsExcluded !== true, 'privacy_source_document_boundary_invalid');
  addReason(reasons, boundary?.disclosureLogRequired !== true, 'privacy_disclosure_log_requirement_absent');
  addReason(reasons, boundary?.telemetryRawPayloadDisabled !== true, 'privacy_raw_telemetry_forbidden');
}

function evaluateAuditTrail(auditTrail, reasons) {
  const families = sortedTextList(auditTrail?.completeEventFamilies);
  addReason(reasons, !hasText(auditTrail?.policyRef), 'audit_trail_policy_ref_absent');
  addReason(reasons, !isDigest(auditTrail?.policyHash), 'audit_trail_policy_hash_invalid');
  addReason(reasons, auditTrail?.appendOnly !== true, 'audit_trail_append_only_absent');
  addReason(reasons, auditTrail?.tamperEvident !== true, 'audit_trail_tamper_evidence_absent');
  addReason(reasons, hlcTuple(auditTrail?.lastVerifiedAtHlc) === null, 'audit_trail_verified_time_invalid');

  for (const family of REQUIRED_AUDIT_EVENT_FAMILIES) {
    addReason(reasons, !families.includes(family), `audit_trail_family_missing:${family}`);
  }
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === null || ai === undefined || ai?.used !== true) {
    return;
  }

  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_review_human_review_absent');
  addReason(reasons, !isDigest(ai.scopeHash), 'ai_scope_hash_invalid');
  addReason(reasons, sortedTextList(ai.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !Array.isArray(ai.limitationHashes), 'ai_limitation_hashes_invalid');
  for (const limitationHash of Array.isArray(ai.limitationHashes) ? ai.limitationHashes : []) {
    addReason(reasons, !isDigest(limitationHash), 'ai_limitation_hash_invalid');
  }
}

function buildValidationRecord(input, validationEvidence, reliabilityScenarios, reasons) {
  const denied = reasons.length > 0;
  const evidenceTypes = sortedTextList(validationEvidence.map((item) => item.evidenceType));
  const scenarioTypes = sortedTextList(reliabilityScenarios.map((item) => item.scenario));
  const openCritical = Number.isSafeInteger(input?.release?.openCriticalDefectCount) ? input.release.openCriticalDefectCount : 0;
  const openMajor = Number.isSafeInteger(input?.release?.openMajorDefectCount) ? input.release.openMajorDefectCount : 0;
  const integrationRequired = input?.integrationReadiness?.required === true;
  const integrationReady =
    integrationRequired ?
      input?.integrationReadiness?.status === 'ready' :
      input?.integrationReadiness?.required === false && input?.integrationReadiness?.status === 'not_applicable';

  const material = {
    evidenceTypes,
    integrationReady,
    integrationRequired,
    releaseRef: hasText(input?.release?.releaseRef) ? input.release.releaseRef : null,
    reliabilityScenarios: scenarioTypes,
    systemRef: hasText(input?.system?.systemRef) ? input.system.systemRef : null,
    systemType: hasText(input?.system?.systemType) ? input.system.systemType : null,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    validatedAtHlc: input?.release?.validatedAtHlc ?? null,
    validationPlanRef: hasText(input?.validationPlan?.planRef) ? input.validationPlan.planRef : null,
    validationPlanVersion: hasText(input?.validationPlan?.planVersion) ? input.validationPlan.planVersion : null,
  };
  const validationHash = sha256Hex(material);

  return {
    schema: ELECTRONIC_SYSTEM_VALIDATION_SCHEMA,
    validationRecordId: `cmesv_${validationHash.slice(0, 32)}`,
    validationHash,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    systemRef: hasText(input?.system?.systemRef) ? input.system.systemRef : null,
    systemType: hasText(input?.system?.systemType) ? input.system.systemType : null,
    protocolRef: hasText(input?.system?.protocolRef) ? input.system.protocolRef : null,
    siteRef: hasText(input?.system?.siteRef) ? input.system.siteRef : null,
    evidenceTypes,
    reliabilityScenarios: scenarioTypes,
    validationEvidenceCount: validationEvidence.length,
    reliabilityScenarioCount: reliabilityScenarios.length,
    trialDataCollectionSystem: input?.system?.dataCollectionUse === true,
    systemValidated: !denied,
    reliabilityVerified: !denied,
    integrationReadinessRequired: integrationRequired,
    integrationReady,
    openDefectCount: openCritical + openMajor,
    metadataOnly: input?.system?.metadataOnly === true,
    sourcePayloadsStayExternal: input?.system?.sourcePayloadsRemainExternal === true,
    aiAssisted: input?.aiAssistance?.used === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, validationRecord) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'electronic_system_validation',
    artifactVersion: `${input.system.systemRef}:${input.system.versionRef}`,
    artifactHash: validationRecord.validationHash,
    classification: 'system_validation_metadata_only',
    hlcTimestamp: input.release.validatedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: [
      'clinical_system_metadata',
      'metadata_only',
      'qms_validation',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.electronic_system_validation',
  });
}

export function evaluateElectronicSystemValidation(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateSystem(input?.system, reasons);
  evaluateValidationPlan(input?.validationPlan, reasons);
  const validationEvidence = normalizeValidationEvidence(input, reasons);
  evaluateReliabilityPlan(input?.reliabilityPlan, reasons);
  const reliabilityScenarios = normalizeReliabilityScenarios(input, reasons);
  evaluateRelease(input, validationEvidence, reasons);
  evaluateIntegrationReadiness(input?.integrationReadiness, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateAuditTrail(input?.auditTrail, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const validationRecord = buildValidationRecord(input, validationEvidence, reliabilityScenarios, unique);

  return {
    schema: ELECTRONIC_SYSTEM_VALIDATION_SCHEMA,
    decision: unique.length > 0 ? 'denied' : 'permitted',
    failClosed: unique.length > 0,
    reasons: unique,
    tenantId: input?.tenantId ?? null,
    targetTenantId: input?.targetTenantId ?? null,
    validationRecord,
    receipt: unique.length > 0 ? null : buildReceipt(input, validationRecord),
  };
}
