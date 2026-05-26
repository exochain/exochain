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
const REQUIRED_PERMISSION = 'manage_participant_visits';
const VISIT_SCHEMA = 'cybermedica.participant_visit_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.participant_visit_readiness_decision.v1';

const REQUIRED_VISIT_DOMAINS = Object.freeze([
  'active_consent_version',
  'delegated_staff_assignment',
  'eligibility_status',
  'participant_communication',
  'procedure_checklist',
  'product_accountability',
  'safety_assessment_plan',
  'source_data_capture',
  'specimen_collection_plan',
  'visit_window_control',
]);

const VISIT_TYPES = new Set([
  'baseline',
  'early_termination',
  'follow_up',
  'screening',
  'treatment',
  'unscheduled',
]);

const VISIT_STATUSES = new Set(['ready', 'scheduled']);
const READINESS_STATUSES = new Set(['ready']);

const RAW_VISIT_FIELDS = new Set([
  'directidentifier',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'patientname',
  'raweligibilitynote',
  'rawparticipantdata',
  'rawpayload',
  'rawproceduredata',
  'rawsource',
  'rawvisit',
  'rawvisitbody',
  'rawvisitnotes',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
  'visitbody',
  'visitnote',
  'visitnotes',
]);

const SECRET_VISIT_FIELDS = new Set([
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

function assertNoRawVisitContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawVisitContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_VISIT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw participant visit content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_VISIT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`participant visit secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawVisitContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawVisitContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'participant_visit_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateVisitPlan(plan, reasons) {
  addReason(reasons, plan === null || plan === undefined, 'visit_plan_absent');
  addReason(reasons, !hasText(plan?.visitRef), 'visit_ref_absent');
  addReason(reasons, !VISIT_TYPES.has(plan?.visitType), 'visit_type_invalid');
  addReason(reasons, !VISIT_STATUSES.has(plan?.status), 'visit_status_invalid');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !isDigest(plan?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(plan?.activeProtocolVersionRef), 'active_protocol_version_ref_absent');
  addReason(reasons, !hasText(plan?.activeConsentMaterialRef), 'active_consent_material_ref_absent');
  addReason(reasons, !isDigest(plan?.procedureScheduleHash), 'procedure_schedule_hash_invalid');
  addReason(reasons, !isDigest(plan?.visitChecklistHash), 'visit_checklist_hash_invalid');
  addReason(reasons, hlcTuple(plan?.visitWindowOpenHlc) === null, 'visit_window_open_time_invalid');
  addReason(reasons, hlcTuple(plan?.scheduledStartHlc) === null, 'visit_start_time_invalid');
  addReason(reasons, hlcTuple(plan?.scheduledEndHlc) === null, 'visit_end_time_invalid');
  addReason(reasons, hlcTuple(plan?.visitWindowCloseHlc) === null, 'visit_window_close_time_invalid');
  addReason(reasons, hlcAfter(plan?.visitWindowOpenHlc, plan?.visitWindowCloseHlc), 'visit_window_close_before_open');
  addReason(reasons, !hlcAfter(plan?.scheduledEndHlc, plan?.scheduledStartHlc), 'visit_end_not_after_start');
  addReason(
    reasons,
    hlcBefore(plan?.scheduledStartHlc, plan?.visitWindowOpenHlc) ||
      hlcAfter(plan?.scheduledStartHlc, plan?.visitWindowCloseHlc),
    'visit_start_outside_window',
  );
  addReason(reasons, hlcAfter(plan?.scheduledEndHlc, plan?.visitWindowCloseHlc), 'visit_end_outside_window');
  addReason(reasons, plan?.metadataOnly !== true, 'visit_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'visit_plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  const requiredDomains = sortedTextList(plan?.requiredVisitDomains);
  evaluateRequiredSet(
    requiredDomains,
    REQUIRED_VISIT_DOMAINS,
    'visit_domain_missing',
    'visit_domain_unsupported',
    reasons,
  );

  return [...REQUIRED_VISIT_DOMAINS];
}

function readinessDomain(check) {
  return hasText(check?.domainRef) ? check.domainRef : 'unclassified_domain';
}

function evaluateReadinessChecks(checks, visitPlan, reasons) {
  addReason(reasons, !Array.isArray(checks), 'readiness_checks_absent');
  const rows = Array.isArray(checks) ? checks : [];
  const seen = new Set();
  const canonicalRows = [];

  for (const check of [...rows].sort((left, right) => readinessDomain(left).localeCompare(readinessDomain(right)))) {
    const domainRef = readinessDomain(check);
    seen.add(domainRef);
    addReason(reasons, !REQUIRED_VISIT_DOMAINS.includes(check?.domainRef), `readiness_check_domain_invalid:${domainRef}`);
    addReason(reasons, !READINESS_STATUSES.has(check?.status), `readiness_check_not_ready:${domainRef}`);
    addReason(reasons, !isDigest(check?.evidenceHash), `readiness_check_evidence_hash_invalid:${domainRef}`);
    addReason(reasons, !hasText(check?.ownerDid), `readiness_check_owner_absent:${domainRef}`);
    addReason(reasons, hlcTuple(check?.completedAtHlc) === null, `readiness_check_time_invalid:${domainRef}`);
    addReason(reasons, !hlcBeforeOrEqual(check?.completedAtHlc, visitPlan?.scheduledStartHlc), `readiness_check_after_visit_start:${domainRef}`);
    addReason(reasons, check?.metadataOnly !== true, `readiness_check_metadata_boundary_invalid:${domainRef}`);
    addReason(reasons, check?.protectedContentExcluded !== true, `readiness_check_protected_boundary_invalid:${domainRef}`);
    canonicalRows.push({
      domainRef,
      evidenceHash: check?.evidenceHash,
      ownerDid: check?.ownerDid,
      status: check?.status,
    });
  }

  for (const domainRef of REQUIRED_VISIT_DOMAINS) {
    addReason(reasons, !seen.has(domainRef), `readiness_check_missing:${domainRef}`);
  }

  return canonicalRows;
}

function evaluateParticipantReadiness(participant, visitPlan, reasons) {
  addReason(reasons, participant === null || participant === undefined, 'participant_readiness_absent');
  addReason(reasons, participant?.participantStatus !== 'active', 'participant_not_active');
  addReason(reasons, participant?.consentStatus !== 'active', 'participant_consent_not_active');
  addReason(reasons, !hasText(participant?.codeAssignmentRef), 'participant_code_assignment_ref_absent');
  addReason(reasons, !hasText(participant?.consentProcessRef), 'consent_process_ref_absent');
  addReason(reasons, !hasText(participant?.currentConsentMaterialRef), 'current_consent_material_ref_absent');
  addReason(
    reasons,
    hasText(participant?.currentConsentMaterialRef) &&
      hasText(visitPlan?.activeConsentMaterialRef) &&
      participant.currentConsentMaterialRef !== visitPlan.activeConsentMaterialRef,
    'participant_consent_material_mismatch',
  );
  addReason(reasons, participant?.reconsentRequired === true, 'reconsent_required_before_visit');
  addReason(reasons, participant?.withdrawalStatus !== 'not_withdrawn', 'participant_withdrawn_or_disposition_blocked');
  addReason(reasons, participant?.lostToFollowUp === true, 'participant_lost_to_follow_up');
  addReason(reasons, !isDigest(participant?.dataUseBoundaryHash), 'data_use_boundary_hash_invalid');
  addReason(reasons, participant?.participantIdentifierSuppressed !== true, 'participant_identifier_boundary_invalid');
  addReason(reasons, participant?.metadataOnly !== true, 'participant_readiness_metadata_boundary_invalid');
  addReason(reasons, participant?.protectedContentExcluded !== true, 'participant_readiness_protected_boundary_invalid');
}

function evaluateStaffReadiness(staff, actor, reasons) {
  addReason(reasons, staff === null || staff === undefined, 'staff_readiness_absent');
  addReason(reasons, !hasText(staff?.assignedStaffDid), 'assigned_staff_absent');
  addReason(
    reasons,
    hasText(staff?.assignedStaffDid) && hasText(actor?.did) && staff.assignedStaffDid !== actor.did,
    'assigned_staff_actor_mismatch',
  );
  addReason(reasons, !hasText(staff?.investigatorDid), 'investigator_absent');
  addReason(reasons, sortedTextList(staff?.delegatedTaskRefs).length === 0, 'delegated_task_refs_absent');
  addReason(reasons, !isDigest(staff?.trainingMatrixHash), 'training_matrix_hash_invalid');
  addReason(reasons, !isDigest(staff?.delegationLogHash), 'delegation_log_hash_invalid');
  addReason(reasons, staff?.allRequiredStaffTrained !== true, 'required_staff_training_incomplete');
  addReason(reasons, staff?.allRequiredTasksDelegated !== true, 'required_task_delegation_incomplete');
  addReason(reasons, staff?.investigatorAvailable !== true, 'investigator_unavailable');
  addReason(reasons, !isDigest(staff?.backupCoverageHash), 'backup_coverage_hash_invalid');
  addReason(reasons, staff?.metadataOnly !== true, 'staff_readiness_metadata_boundary_invalid');
  addReason(reasons, staff?.protectedContentExcluded !== true, 'staff_readiness_protected_boundary_invalid');
}

function evaluateMaterialsReadiness(materials, reasons) {
  addReason(reasons, materials === null || materials === undefined, 'materials_readiness_absent');
  addReason(reasons, !hasText(materials?.specimenLifecycleReadinessRef), 'specimen_lifecycle_readiness_ref_absent');
  addReason(reasons, !hasText(materials?.facilityProductReadinessRef), 'facility_product_readiness_ref_absent');
  addReason(reasons, sortedTextList(materials?.activeDocumentVersionRefs).length === 0, 'active_document_version_refs_absent');
  addReason(reasons, !isDigest(materials?.equipmentCalibrationHash), 'equipment_calibration_hash_invalid');
  addReason(reasons, !isDigest(materials?.productAccountabilityHash), 'product_accountability_hash_invalid');
  addReason(reasons, !isDigest(materials?.kitReadinessHash), 'kit_readiness_hash_invalid');
  addReason(reasons, !isDigest(materials?.sourceDataWorksheetHash), 'source_data_worksheet_hash_invalid');
  addReason(reasons, !isDigest(materials?.privacyBoundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, materials?.metadataOnly !== true, 'materials_readiness_metadata_boundary_invalid');
  addReason(reasons, materials?.protectedContentExcluded !== true, 'materials_readiness_protected_boundary_invalid');
}

function evaluateOperationalControls(controls, reasons) {
  addReason(reasons, controls === null || controls === undefined, 'operational_controls_absent');
  addReason(reasons, !hasText(controls?.launchGateRef), 'launch_gate_ref_absent');
  addReason(reasons, !hasText(controls?.enrollmentGateRef), 'enrollment_gate_ref_absent');
  addReason(reasons, controls?.launchAuthorized !== true, 'launch_gate_not_authorized');
  addReason(reasons, controls?.enrollmentAuthorized !== true, 'enrollment_gate_not_authorized');
  addReason(reasons, controls?.noVisitBeforeLaunchAuthorization !== true, 'visit_before_launch_authorization_forbidden');
  addReason(reasons, !isDigest(controls?.dueDateNotificationHash), 'due_date_notification_hash_invalid');
  addReason(reasons, !isDigest(controls?.deviationEscalationPathHash), 'deviation_escalation_path_hash_invalid');
  addReason(reasons, !isDigest(controls?.safetyEventEscalationPathHash), 'safety_event_escalation_path_hash_invalid');
  addReason(reasons, !isDigest(controls?.visitReminderPolicyHash), 'visit_reminder_policy_hash_invalid');
  addReason(reasons, !isDigest(controls?.missedVisitProcedureHash), 'missed_visit_procedure_hash_invalid');
  addReason(reasons, !isDigest(controls?.unscheduledVisitProcedureHash), 'unscheduled_visit_procedure_hash_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'operational_controls_metadata_boundary_invalid');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'operational_controls_protected_boundary_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'review_evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_attestation_absent');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function createParticipantVisitReadiness(input, readinessChecks) {
  const delegatedTaskRefs = sortedTextList(input.staffReadiness.delegatedTaskRefs);
  const activeDocumentVersionRefs = sortedTextList(input.materialsReadiness.activeDocumentVersionRefs);
  const readinessId = `cm_visit_${sha256Hex({
    schema: VISIT_SCHEMA,
    activeConsentMaterialRef: input.visitPlan.activeConsentMaterialRef,
    activeDocumentVersionRefs,
    activeProtocolVersionRef: input.visitPlan.activeProtocolVersionRef,
    delegatedTaskRefs,
    participantCodeHash: input.visitPlan.participantCodeHash,
    protocolRef: input.visitPlan.protocolRef,
    readinessChecks,
    siteRef: input.visitPlan.siteRef,
    tenantId: input.tenantId,
    visitRef: input.visitPlan.visitRef,
  }).slice(0, 32)}`;

  return {
    schema: VISIT_SCHEMA,
    readinessId,
    tenantId: input.tenantId,
    siteRef: input.visitPlan.siteRef,
    protocolRef: input.visitPlan.protocolRef,
    visitRef: input.visitPlan.visitRef,
    visitType: input.visitPlan.visitType,
    participantCodeHash: input.visitPlan.participantCodeHash,
    activeProtocolVersionRef: input.visitPlan.activeProtocolVersionRef,
    activeConsentMaterialRef: input.visitPlan.activeConsentMaterialRef,
    visitDomainsCovered: [...REQUIRED_VISIT_DOMAINS],
    readinessCheckCount: readinessChecks.length,
    delegatedTaskRefs,
    activeDocumentVersionRefs,
    visitWindowStatus: 'within_window',
    participantContinuationStatus: 'eligible_for_visit',
    staffReadinessStatus: 'ready',
    materialsReadinessStatus: 'ready',
    operationalGateStatus: 'authorized',
    readinessStatus: 'ready_for_visit_execution',
    requiredEscalationRoles: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
  };
}

function createVisitReceipt(input, participantVisitReadiness) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'participant_visit_readiness',
    artifactVersion: '1',
    artifactHash: sha256Hex({
      schema: VISIT_SCHEMA,
      participantVisitReadiness,
    }),
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.visitPlan.scheduledStartHlc,
    classification: 'metadata_only_participant_visit_readiness',
    sensitivityTags: ['clinical_operations', 'participant_pseudonymous', 'qms_metadata'],
    sourceSystem: 'cybermedica',
  });
}

export function evaluateParticipantVisitReadiness(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateVisitPlan(input?.visitPlan, reasons);
  const readinessChecks = evaluateReadinessChecks(input?.readinessChecks, input?.visitPlan, reasons);
  evaluateParticipantReadiness(input?.participantReadiness, input?.visitPlan, reasons);
  evaluateStaffReadiness(input?.staffReadiness, input?.actor, reasons);
  evaluateMaterialsReadiness(input?.materialsReadiness, reasons);
  evaluateOperationalControls(input?.operationalControls, reasons);
  evaluateHumanReview(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      participantVisitReadiness: null,
      receipt: null,
    };
  }

  const participantVisitReadiness = createParticipantVisitReadiness(input, readinessChecks);
  const receipt = createVisitReceipt(input, participantVisitReadiness);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    participantVisitReadiness,
    receipt,
  };
}

export const participantVisitReadinessRequirements = Object.freeze({
  schema: VISIT_SCHEMA,
  requiredPermission: REQUIRED_PERMISSION,
  requiredVisitDomains: REQUIRED_VISIT_DOMAINS,
  productionTrustState: 'inactive',
});
