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
const AVAILABILITY_RECOVERY_SCHEMA = 'cybermedica.availability_recovery_readiness.v1';
const REQUIRED_PERMISSION = 'availability_readiness';
const MAX_BASIS_POINTS = 10000;

const SERVICE_FAMILIES = new Set([
  'api_gateway',
  'browser_gateway',
  'evidence_store',
  'identity_provider',
  'integration_gateway',
  'qms_core',
  'receipt_adapter',
]);

const REQUIRED_PROCEDURES = Object.freeze([
  'availability',
  'backup',
  'business_continuity',
  'disaster_recovery',
  'maintenance',
  'recovery',
]);

const REQUIRED_MONITORING_SIGNALS = Object.freeze([
  'dependency_health',
  'process_uptime',
  'receipt_queue',
  'restore_point_age',
  'trust_readiness',
]);

const REQUIRED_BACKUP_FAMILIES = Object.freeze([
  'audit_trails',
  'evidence_indexes',
  'metadata_records',
  'receipt_refs',
  'tenant_configs',
]);

const REQUIRED_RESTORE_SCENARIOS = Object.freeze([
  'audit_record_restore',
  'evidence_index_restore',
  'metadata_database_restore',
  'receipt_queue_replay',
]);

const REQUIRED_DR_SCENARIOS = Object.freeze([
  'identity_provider_degraded',
  'object_storage_unavailable',
  'primary_region_unavailable',
  'receipt_adapter_unavailable',
]);

const REQUIRED_CRITICAL_WORKFLOWS = Object.freeze([
  'consent_update',
  'decision_forum',
  'enrollment_gate',
  'reporting',
  'safety_event',
]);

const REQUIRED_AUDIT_EVENT_FAMILIES = Object.freeze([
  'backup',
  'failover',
  'incident',
  'maintenance',
  'monitoring',
  'privileged_action',
  'restore',
]);

const PROCEDURE_STATUSES = new Set(['approved', 'tested']);
const MONITORING_STATUSES = new Set(['healthy']);
const SIGNAL_STATUSES = new Set(['passing']);
const BACKUP_STATUSES = new Set(['verified']);
const CONTINUITY_STATUSES = new Set(['approved', 'tested']);
const DISASTER_RECOVERY_STATUSES = new Set(['tested']);
const RESTORE_TARGET_ENVIRONMENTS = new Set(['isolated_validation', 'validated_recovery_environment']);

const RAW_AVAILABILITY_FIELDS = new Set([
  'backuparchivebody',
  'backupcontent',
  'backuppayload',
  'databasebackup',
  'databasedump',
  'freetextrunbook',
  'incidentnarrative',
  'logbody',
  'rawavailabilitydata',
  'rawbackup',
  'rawbackuppayload',
  'rawhealthresponse',
  'rawincident',
  'rawlog',
  'rawmonitoringdata',
  'rawpayload',
  'rawrestore',
  'rawrestoredata',
  'restoreddatabasedump',
  'restoredatabasedump',
  'restorepayload',
  'sourcepayload',
]);

const SECRET_AVAILABILITY_FIELDS = new Set([
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

function assertNoRawAvailabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAvailabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AVAILABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw availability or recovery content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AVAILABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`availability or recovery secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAvailabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAvailabilityContent(input ?? {});
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

function validBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_BASIS_POINTS;
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
    'availability_readiness_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateService(service, reasons) {
  addReason(reasons, !hasText(service?.serviceRef), 'service_ref_absent');
  addReason(reasons, !SERVICE_FAMILIES.has(service?.serviceFamily), 'service_family_invalid');
  addReason(reasons, !hasText(service?.siteRef), 'service_site_ref_absent');
  addReason(reasons, !hasText(service?.protocolRef), 'service_protocol_ref_absent');
  addReason(reasons, !hasText(service?.ownerDid), 'service_owner_absent');
  addReason(reasons, !hasText(service?.backupOwnerDid), 'service_backup_owner_absent');
  addReason(reasons, !isDigest(service?.escalationPathHash), 'service_escalation_path_hash_invalid');
  addReason(reasons, !isDigest(service?.rollbackDisablementHash), 'service_rollback_disablement_hash_invalid');
  addReason(reasons, !isDigest(service?.dependencyMapHash), 'service_dependency_map_hash_invalid');
  addReason(reasons, !isDigest(service?.maintenanceRunbookHash), 'service_maintenance_runbook_hash_invalid');
  addReason(reasons, !isDigest(service?.configurationHash), 'service_configuration_hash_invalid');
  addReason(reasons, service?.metadataOnly !== true, 'service_metadata_boundary_invalid');
  addReason(reasons, service?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizeProcedures(plan, reasons) {
  const procedures = Array.isArray(plan?.procedureRefs) ? plan.procedureRefs : [];
  addReason(reasons, procedures.length === 0, 'availability_procedures_absent');

  const byType = new Map();
  for (const procedure of procedures) {
    if (hasText(procedure?.procedureType)) {
      addReason(reasons, byType.has(procedure.procedureType), `availability_procedure_duplicate:${procedure.procedureType}`);
      byType.set(procedure.procedureType, procedure);
    }
  }

  const normalized = [];
  for (const procedureType of REQUIRED_PROCEDURES) {
    const procedure = byType.get(procedureType);
    if (procedure === undefined) {
      reasons.push(`availability_procedure_missing:${procedureType}`);
      continue;
    }

    const procedureRef = hasText(procedure?.procedureRef) ? procedure.procedureRef : 'unknown';
    addReason(reasons, !hasText(procedure?.procedureRef), `availability_procedure_ref_absent:${procedureType}`);
    addReason(reasons, !isDigest(procedure?.procedureHash), `availability_procedure_hash_invalid:${procedureRef}`);
    addReason(reasons, !PROCEDURE_STATUSES.has(procedure?.status), `availability_procedure_status_invalid:${procedureRef}`);
    addReason(reasons, !hasText(procedure?.ownerDid), `availability_procedure_owner_absent:${procedureRef}`);
    addReason(reasons, !hasText(procedure?.backupOwnerDid), `availability_procedure_backup_owner_absent:${procedureRef}`);
    addReason(reasons, hlcTuple(procedure?.reviewedAtHlc) === null, `availability_procedure_review_time_invalid:${procedureRef}`);
    addReason(
      reasons,
      hlcBefore(procedure?.reviewedAtHlc, plan?.approvedAtHlc),
      `availability_procedure_review_before_plan_approval:${procedureRef}`,
    );
    addReason(reasons, !isDigest(procedure?.evidenceHash), `availability_procedure_evidence_hash_invalid:${procedureRef}`);
    addReason(reasons, procedure?.metadataOnly !== true, `availability_procedure_metadata_boundary_invalid:${procedureRef}`);

    normalized.push({
      evidenceHash: procedure?.evidenceHash ?? null,
      procedureHash: procedure?.procedureHash ?? null,
      procedureRef,
      procedureType,
    });
  }

  return normalized.sort((left, right) => left.procedureType.localeCompare(right.procedureType));
}

function evaluateAvailabilityPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'availability_plan_ref_absent');
  addReason(reasons, !hasText(plan?.planVersion), 'availability_plan_version_absent');
  addReason(reasons, plan?.approved !== true, 'availability_plan_not_approved');
  addReason(reasons, !hasText(plan?.approvedByDid), 'availability_plan_approver_absent');
  addReason(reasons, hlcTuple(plan?.approvedAtHlc) === null, 'availability_plan_approval_time_invalid');
  addReason(reasons, !isDigest(plan?.approvalHash), 'availability_plan_approval_hash_invalid');
  addReason(reasons, !isPositiveSafeInteger(plan?.rtoMinutes), 'availability_rto_invalid');
  addReason(reasons, !isPositiveSafeInteger(plan?.rpoMinutes), 'availability_rpo_invalid');
  addReason(reasons, !isPositiveSafeInteger(plan?.maxTolerableDowntimeMinutes), 'max_tolerable_downtime_invalid');
  addReason(
    reasons,
    isPositiveSafeInteger(plan?.rtoMinutes) &&
      isPositiveSafeInteger(plan?.maxTolerableDowntimeMinutes) &&
      plan.maxTolerableDowntimeMinutes < plan.rtoMinutes,
    'max_tolerable_downtime_below_rto',
  );
  addReason(reasons, !isDigest(plan?.continuityRiskAssessmentHash), 'continuity_risk_assessment_hash_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'availability_plan_metadata_boundary_invalid');
}

function normalizeMonitoringSignals(monitoring, reasons) {
  const signals = Array.isArray(monitoring?.signals) ? monitoring.signals : [];
  addReason(reasons, signals.length === 0, 'monitoring_signals_absent');

  const byType = new Map();
  for (const signal of signals) {
    if (hasText(signal?.signalType)) {
      addReason(reasons, byType.has(signal.signalType), `monitoring_signal_duplicate:${signal.signalType}`);
      byType.set(signal.signalType, signal);
    }
  }

  const normalized = [];
  for (const signalType of REQUIRED_MONITORING_SIGNALS) {
    const signal = byType.get(signalType);
    if (signal === undefined) {
      reasons.push(`monitoring_signal_missing:${signalType}`);
      continue;
    }

    addReason(reasons, !SIGNAL_STATUSES.has(signal?.status), `monitoring_signal_not_passing:${signalType}`);
    addReason(reasons, !isDigest(signal?.evidenceHash), `monitoring_signal_evidence_hash_invalid:${signalType}`);
    addReason(reasons, hlcTuple(signal?.measuredAtHlc) === null, `monitoring_signal_time_invalid:${signalType}`);
    addReason(
      reasons,
      hlcAfter(signal?.measuredAtHlc, monitoring?.evaluatedAtHlc),
      `monitoring_signal_after_evaluation:${signalType}`,
    );
    addReason(reasons, signal?.metadataOnly !== true, `monitoring_signal_metadata_boundary_invalid:${signalType}`);

    normalized.push({
      evidenceHash: signal?.evidenceHash ?? null,
      measuredAtHlc: signal?.measuredAtHlc ?? null,
      signalType,
    });
  }

  return normalized.sort((left, right) => left.signalType.localeCompare(right.signalType));
}

function evaluateMonitoring(monitoring, reasons) {
  addReason(reasons, !hasText(monitoring?.monitorRef), 'monitoring_ref_absent');
  addReason(reasons, !MONITORING_STATUSES.has(monitoring?.status), 'monitoring_not_healthy');
  addReason(reasons, hlcTuple(monitoring?.evaluatedAtHlc) === null, 'monitoring_evaluation_time_invalid');
  addReason(reasons, !validBasisPoints(monitoring?.uptimeBasisPoints), 'uptime_basis_points_invalid');
  addReason(reasons, !validBasisPoints(monitoring?.thresholdBasisPoints), 'uptime_threshold_basis_points_invalid');
  addReason(
    reasons,
    validBasisPoints(monitoring?.uptimeBasisPoints) &&
      validBasisPoints(monitoring?.thresholdBasisPoints) &&
      monitoring.uptimeBasisPoints < monitoring.thresholdBasisPoints,
    'uptime_below_threshold',
  );
  addReason(reasons, !isDigest(monitoring?.monitoringEvidenceHash), 'monitoring_evidence_hash_invalid');
  addReason(reasons, !isDigest(monitoring?.alertRouteHash), 'monitoring_alert_route_hash_invalid');
  addReason(reasons, !isDigest(monitoring?.onCallScheduleHash), 'monitoring_on_call_schedule_hash_invalid');
  addReason(reasons, !isDigest(monitoring?.lastIncidentRunbookHash), 'monitoring_incident_runbook_hash_invalid');
}

function evaluateBackup(backup, plan, reasons) {
  const families = sortedTextList(backup?.backupFamilies);
  addReason(reasons, !hasText(backup?.backupPolicyRef), 'backup_policy_ref_absent');
  addReason(reasons, !BACKUP_STATUSES.has(backup?.status), 'backup_not_verified');
  addReason(reasons, !isDigest(backup?.scheduleHash), 'backup_schedule_hash_invalid');
  addReason(reasons, !isDigest(backup?.backupManifestHash), 'backup_manifest_hash_invalid');
  addReason(reasons, !isDigest(backup?.lastBackupDigest), 'backup_digest_invalid');
  addReason(reasons, hlcTuple(backup?.lastSuccessfulBackupAtHlc) === null, 'backup_success_time_invalid');
  addReason(reasons, hlcBefore(backup?.lastSuccessfulBackupAtHlc, plan?.approvedAtHlc), 'backup_before_plan_approval');
  addReason(reasons, !isNonNegativeSafeInteger(backup?.restorePointAgeMinutes), 'restore_point_age_invalid');
  addReason(
    reasons,
    isNonNegativeSafeInteger(backup?.restorePointAgeMinutes) &&
      isPositiveSafeInteger(plan?.rpoMinutes) &&
      backup.restorePointAgeMinutes > plan.rpoMinutes,
    'restore_point_exceeds_rpo',
  );
  addReason(reasons, !isPositiveSafeInteger(backup?.retentionDays), 'backup_retention_days_invalid');
  addReason(reasons, backup?.encryptedAtRest !== true, 'backup_encryption_absent');
  addReason(reasons, backup?.offsiteCopy !== true, 'backup_offsite_copy_absent');
  addReason(reasons, backup?.immutableCopy !== true, 'backup_immutable_copy_absent');
  addReason(reasons, backup?.metadataOnly !== true, 'backup_metadata_boundary_invalid');
  addReason(reasons, backup?.payloadsRemainExternal !== true, 'backup_payload_boundary_invalid');

  for (const family of REQUIRED_BACKUP_FAMILIES) {
    addReason(reasons, !families.includes(family), `backup_family_missing:${family}`);
  }

  return families;
}

function normalizeRestoreTests(input, reasons) {
  const restoreTests = Array.isArray(input?.restoreTests) ? input.restoreTests : [];
  addReason(reasons, restoreTests.length === 0, 'restore_tests_absent');

  const byScenario = new Map();
  for (const test of restoreTests) {
    if (hasText(test?.scenario)) {
      addReason(reasons, byScenario.has(test.scenario), `restore_scenario_duplicate:${test.scenario}`);
      byScenario.set(test.scenario, test);
    }
  }

  const normalized = [];
  for (const scenario of REQUIRED_RESTORE_SCENARIOS) {
    const test = byScenario.get(scenario);
    if (test === undefined) {
      reasons.push(`restore_scenario_missing:${scenario}`);
      continue;
    }

    const evidenceRef = hasText(test?.evidenceRef) ? test.evidenceRef : 'unknown';
    addReason(reasons, !hasText(test?.evidenceRef), `restore_evidence_ref_absent:${scenario}`);
    addReason(reasons, !isDigest(test?.backupDigest), `restore_backup_digest_invalid:${evidenceRef}`);
    addReason(reasons, test?.backupDigest !== input?.backup?.lastBackupDigest, `restore_backup_digest_mismatch:${evidenceRef}`);
    addReason(reasons, !isDigest(test?.restoredArtifactHash), `restore_artifact_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(test?.reconciliationHash), `restore_reconciliation_hash_invalid:${evidenceRef}`);
    addReason(reasons, hlcTuple(test?.executedAtHlc) === null, `restore_execution_time_invalid:${evidenceRef}`);
    addReason(reasons, hlcBefore(test?.executedAtHlc, input?.backup?.lastSuccessfulBackupAtHlc), `restore_executed_before_backup:${evidenceRef}`);
    addReason(reasons, test?.passed !== true, `restore_scenario_not_passed:${scenario}`);
    addReason(reasons, test?.dataIntegrityVerified !== true, `restore_data_integrity_absent:${scenario}`);
    addReason(reasons, test?.protectedContentExcluded !== true, `restore_protected_content_boundary_invalid:${scenario}`);
    addReason(reasons, !RESTORE_TARGET_ENVIRONMENTS.has(test?.targetEnvironment), `restore_target_environment_invalid:${scenario}`);

    normalized.push({
      evidenceRef,
      reconciliationHash: test?.reconciliationHash ?? null,
      restoredArtifactHash: test?.restoredArtifactHash ?? null,
      scenario,
    });
  }

  return normalized.sort((left, right) => left.scenario.localeCompare(right.scenario));
}

function evaluateContinuity(continuity, reasons) {
  const workflows = sortedTextList(continuity?.criticalWorkflowRefs);
  addReason(reasons, !hasText(continuity?.runbookRef), 'continuity_runbook_ref_absent');
  addReason(reasons, !CONTINUITY_STATUSES.has(continuity?.status), 'continuity_not_approved');
  addReason(reasons, !isDigest(continuity?.continuityPlanHash), 'continuity_plan_hash_invalid');
  addReason(reasons, !isDigest(continuity?.communicationsPlanHash), 'continuity_communications_plan_hash_invalid');
  addReason(reasons, !isDigest(continuity?.manualWorkaroundHash), 'continuity_manual_workaround_hash_invalid');
  addReason(reasons, !hasText(continuity?.onCallOwnerDid), 'continuity_on_call_owner_absent');
  addReason(reasons, !hasText(continuity?.backupOwnerDid), 'continuity_backup_owner_absent');
  addReason(reasons, hlcTuple(continuity?.lastReviewedAtHlc) === null, 'continuity_review_time_invalid');
  addReason(reasons, continuity?.metadataOnly !== true, 'continuity_metadata_boundary_invalid');

  for (const workflow of REQUIRED_CRITICAL_WORKFLOWS) {
    addReason(reasons, !workflows.includes(workflow), `continuity_workflow_missing:${workflow}`);
  }

  return workflows;
}

function normalizeDisasterRecoveryScenarios(dr, plan, reasons) {
  const scenarios = Array.isArray(dr?.scenarios) ? dr.scenarios : [];
  addReason(reasons, scenarios.length === 0, 'disaster_recovery_scenarios_absent');

  const byScenario = new Map();
  for (const scenario of scenarios) {
    if (hasText(scenario?.scenario)) {
      addReason(reasons, byScenario.has(scenario.scenario), `disaster_recovery_scenario_duplicate:${scenario.scenario}`);
      byScenario.set(scenario.scenario, scenario);
    }
  }

  const normalized = [];
  for (const scenarioName of REQUIRED_DR_SCENARIOS) {
    const scenario = byScenario.get(scenarioName);
    if (scenario === undefined) {
      reasons.push(`disaster_recovery_scenario_missing:${scenarioName}`);
      continue;
    }

    addReason(reasons, !isDigest(scenario?.evidenceHash), `disaster_recovery_evidence_hash_invalid:${scenarioName}`);
    addReason(reasons, hlcTuple(scenario?.testedAtHlc) === null, `disaster_recovery_scenario_time_invalid:${scenarioName}`);
    addReason(reasons, hlcBefore(scenario?.testedAtHlc, plan?.approvedAtHlc), `disaster_recovery_scenario_before_plan_approval:${scenarioName}`);
    addReason(reasons, scenario?.passed !== true, `disaster_recovery_scenario_not_passed:${scenarioName}`);
    addReason(reasons, scenario?.failClosedObserved !== true, `disaster_recovery_fail_closed_absent:${scenarioName}`);
    addReason(reasons, !isNonNegativeSafeInteger(scenario?.rtoObservedMinutes), `disaster_recovery_rto_observed_invalid:${scenarioName}`);
    addReason(reasons, !isNonNegativeSafeInteger(scenario?.rpoObservedMinutes), `disaster_recovery_rpo_observed_invalid:${scenarioName}`);
    addReason(
      reasons,
      isNonNegativeSafeInteger(scenario?.rtoObservedMinutes) &&
        isPositiveSafeInteger(plan?.rtoMinutes) &&
        scenario.rtoObservedMinutes > plan.rtoMinutes,
      `disaster_recovery_rto_exceeded:${scenarioName}`,
    );
    addReason(
      reasons,
      isNonNegativeSafeInteger(scenario?.rpoObservedMinutes) &&
        isPositiveSafeInteger(plan?.rpoMinutes) &&
        scenario.rpoObservedMinutes > plan.rpoMinutes,
      `disaster_recovery_rpo_exceeded:${scenarioName}`,
    );
    addReason(
      reasons,
      scenario?.noDataLossBeyondRpo !== true,
      `disaster_recovery_data_loss_boundary_invalid:${scenarioName}`,
    );

    normalized.push({
      evidenceHash: scenario?.evidenceHash ?? null,
      scenario: scenarioName,
      testedAtHlc: scenario?.testedAtHlc ?? null,
    });
  }

  return normalized.sort((left, right) => left.scenario.localeCompare(right.scenario));
}

function evaluateDisasterRecovery(dr, plan, reasons) {
  addReason(reasons, !hasText(dr?.drPlanRef), 'disaster_recovery_plan_ref_absent');
  addReason(reasons, !DISASTER_RECOVERY_STATUSES.has(dr?.status), 'disaster_recovery_not_tested');
  addReason(reasons, !isDigest(dr?.failoverRunbookHash), 'disaster_recovery_failover_runbook_hash_invalid');
  addReason(reasons, !isDigest(dr?.failbackRunbookHash), 'disaster_recovery_failback_runbook_hash_invalid');
  addReason(reasons, !hasText(dr?.recoverySiteRef), 'disaster_recovery_site_ref_absent');
  addReason(reasons, hlcTuple(dr?.testedAtHlc) === null, 'disaster_recovery_test_time_invalid');
  addReason(reasons, hlcBefore(dr?.testedAtHlc, plan?.approvedAtHlc), 'disaster_recovery_test_before_plan_approval');
  addReason(reasons, !isDigest(dr?.drTestEvidenceHash), 'disaster_recovery_test_evidence_hash_invalid');
  addReason(reasons, dr?.metadataOnly !== true, 'disaster_recovery_metadata_boundary_invalid');
}

function evaluateAuditTrail(auditTrail, reasons) {
  const eventFamilies = sortedTextList(auditTrail?.eventFamilies);
  addReason(reasons, !hasText(auditTrail?.policyRef), 'audit_policy_ref_absent');
  addReason(reasons, !isDigest(auditTrail?.policyHash), 'audit_policy_hash_invalid');
  addReason(reasons, auditTrail?.appendOnly !== true, 'audit_append_only_absent');
  addReason(reasons, auditTrail?.tamperEvident !== true, 'audit_tamper_evidence_absent');
  addReason(reasons, hlcTuple(auditTrail?.lastVerifiedAtHlc) === null, 'audit_verified_time_invalid');

  for (const family of REQUIRED_AUDIT_EVENT_FAMILIES) {
    addReason(reasons, !eventFamilies.includes(family), `audit_event_family_missing:${family}`);
  }
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, boundary?.receiptMetadataOnly !== true, 'privacy_receipt_metadata_boundary_invalid');
  addReason(reasons, boundary?.backupPayloadsStayExternal !== true, 'privacy_backup_payload_boundary_invalid');
  addReason(reasons, boundary?.restoreValidationUsesMetadataOnly !== true, 'privacy_restore_validation_boundary_invalid');
  addReason(reasons, boundary?.rawLogsExcluded !== true, 'privacy_raw_logs_forbidden');
  addReason(reasons, boundary?.secretsExcluded !== true, 'privacy_secret_boundary_invalid');
  addReason(reasons, boundary?.phiPiiExcludedFromReceipts !== true, 'privacy_phi_pii_receipt_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
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

function readinessBooleans(reasons) {
  const text = reasons.join('|');
  return {
    availabilityReady: reasons.length === 0,
    backupReady: reasons.length === 0 || !/backup_|restore_point|restore_|rpo/iu.test(text),
    disasterRecoveryReady: reasons.length === 0 || !/disaster_recovery|rto|rpo|continuity_/iu.test(text),
    recoveryReady: reasons.length === 0 || !/restore_|backup_|disaster_recovery|continuity_/iu.test(text),
  };
}

function buildAvailabilityRecord(input, procedures, monitoringSignals, backupFamilies, restoreTests, drScenarios, reasons) {
  const booleans = readinessBooleans(reasons);
  const procedureTypes = sortedTextList(procedures.map((procedure) => procedure.procedureType));
  const monitoringSignalTypes = sortedTextList(monitoringSignals.map((signal) => signal.signalType));
  const restoreScenarios = sortedTextList(restoreTests.map((test) => test.scenario));
  const disasterRecoveryScenarios = sortedTextList(drScenarios.map((scenario) => scenario.scenario));

  const material = {
    backupFamilies,
    disasterRecoveryScenarios,
    monitoringSignals: monitoringSignalTypes,
    planRef: hasText(input?.availabilityPlan?.planRef) ? input.availabilityPlan.planRef : null,
    planVersion: hasText(input?.availabilityPlan?.planVersion) ? input.availabilityPlan.planVersion : null,
    procedureTypes,
    restoreScenarios,
    serviceRef: hasText(input?.service?.serviceRef) ? input.service.serviceRef : null,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
  };
  const recordHash = sha256Hex(material);

  return {
    schema: AVAILABILITY_RECOVERY_SCHEMA,
    recordId: `cmarr_${recordHash.slice(0, 32)}`,
    recordHash,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    serviceRef: hasText(input?.service?.serviceRef) ? input.service.serviceRef : null,
    serviceFamily: hasText(input?.service?.serviceFamily) ? input.service.serviceFamily : null,
    siteRef: hasText(input?.service?.siteRef) ? input.service.siteRef : null,
    protocolRef: hasText(input?.service?.protocolRef) ? input.service.protocolRef : null,
    ownerDid: hasText(input?.service?.ownerDid) ? input.service.ownerDid : null,
    backupOwnerDid: hasText(input?.service?.backupOwnerDid) ? input.service.backupOwnerDid : null,
    procedureTypes,
    monitoringSignals: monitoringSignalTypes,
    backupFamilies,
    restoreScenarios,
    disasterRecoveryScenarios,
    rtoMinutes: Number.isSafeInteger(input?.availabilityPlan?.rtoMinutes) ? input.availabilityPlan.rtoMinutes : null,
    rpoMinutes: Number.isSafeInteger(input?.availabilityPlan?.rpoMinutes) ? input.availabilityPlan.rpoMinutes : null,
    uptimeBasisPoints: Number.isSafeInteger(input?.monitoring?.uptimeBasisPoints) ? input.monitoring.uptimeBasisPoints : null,
    restorePointAgeMinutes: Number.isSafeInteger(input?.backup?.restorePointAgeMinutes) ? input.backup.restorePointAgeMinutes : null,
    availabilityReady: booleans.availabilityReady,
    backupReady: booleans.backupReady,
    recoveryReady: booleans.recoveryReady,
    disasterRecoveryReady: booleans.disasterRecoveryReady,
    aiAssisted: input?.aiAssistance?.used === true,
    metadataOnly: input?.service?.metadataOnly === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, availabilityRecord) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'availability_recovery_readiness',
    artifactVersion: `${input.service.serviceRef}:${input.availabilityPlan.planVersion}`,
    artifactHash: availabilityRecord.recordHash,
    classification: 'availability_recovery_metadata_only',
    hlcTimestamp: input.monitoring.evaluatedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: [
      'availability_metadata',
      'backup_recovery_metadata',
      'metadata_only',
      'qms_operations',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.availability_recovery_readiness',
  });
}

export function evaluateAvailabilityRecoveryReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateService(input?.service, reasons);
  evaluateAvailabilityPlan(input?.availabilityPlan, reasons);
  const procedures = normalizeProcedures(input?.availabilityPlan, reasons);
  evaluateMonitoring(input?.monitoring, reasons);
  const monitoringSignals = normalizeMonitoringSignals(input?.monitoring, reasons);
  const backupFamilies = evaluateBackup(input?.backup, input?.availabilityPlan, reasons);
  const restoreTests = normalizeRestoreTests(input, reasons);
  const criticalWorkflows = evaluateContinuity(input?.continuity, reasons);
  evaluateDisasterRecovery(input?.disasterRecovery, input?.availabilityPlan, reasons);
  const drScenarios = normalizeDisasterRecoveryScenarios(input?.disasterRecovery, input?.availabilityPlan, reasons);
  evaluateAuditTrail(input?.auditTrail, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const availabilityRecord = buildAvailabilityRecord(
    input,
    procedures,
    monitoringSignals,
    backupFamilies,
    restoreTests,
    drScenarios,
    unique,
  );

  return {
    schema: AVAILABILITY_RECOVERY_SCHEMA,
    decision: unique.length > 0 ? 'denied' : 'permitted',
    failClosed: unique.length > 0,
    reasons: unique,
    tenantId: input?.tenantId ?? null,
    targetTenantId: input?.targetTenantId ?? null,
    criticalWorkflows,
    availabilityRecord,
    receipt: unique.length > 0 ? null : buildReceipt(input, availabilityRecord),
  };
}
