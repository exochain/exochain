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
const REQUIRED_PERMISSION = 'manage_equipment_calibration';
const EQUIPMENT_CALIBRATION_SCHEMA = 'cybermedica.equipment_calibration_readiness.v1';

const REQUIRED_CALIBRATION_DOMAINS = Object.freeze([
  'calibration_evidence',
  'calibration_schedule',
  'calibration_traceability',
  'check_before_use',
  'defect_reporting',
  'equipment_inventory',
  'maintenance_records',
  'quarantine_control',
  'return_to_service',
]);

const ACTIVE_PROGRAM_STATUSES = new Set(['active']);
const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const ACTIVE_EQUIPMENT_STATUSES = new Set(['active', 'in_service']);
const FIT_EQUIPMENT_STATUSES = new Set(['fit_for_use']);
const CLEAR_QUARANTINE_STATUSES = new Set(['not_quarantined']);
const CALIBRATION_EVENT_RESULTS = new Set(['passed']);
const CHECK_RESULTS = new Set(['passed']);
const QUARANTINE_RECORD_STATUSES = new Set(['opened', 'released']);
const REVIEW_DECISIONS = new Set(['equipment_calibration_ready', 'hold_equipment_calibration_gap']);

const RAW_EQUIPMENT_CALIBRATION_FIELDS = new Set([
  'calibrationnarrative',
  'calibrationnote',
  'directidentifier',
  'equipmentrawlog',
  'equipmentserialnumber',
  'participantidentifier',
  'participantname',
  'patientname',
  'rawcalibrationcertificate',
  'rawcalibrationrecord',
  'rawequipment',
  'rawequipmentrecord',
  'rawmaintenancebody',
  'rawpayload',
  'rawserialnumber',
  'serialnumber',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
]);

const SECRET_EQUIPMENT_CALIBRATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'facilitysecret',
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawEquipmentCalibrationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawEquipmentCalibrationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_EQUIPMENT_CALIBRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw equipment calibration field is not allowed at ${path}.${key}`);
    }
    if (SECRET_EQUIPMENT_CALIBRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`equipment calibration secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawEquipmentCalibrationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawEquipmentCalibrationContent(input ?? {});
  canonicalize(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hlcEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) === 0;
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'govern') &&
      !hasAuthorityPermission(input?.authority, 'write'),
    'equipment_calibration_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredDomains(input, reasons) {
  const requiredDomains = sortedTextList(input?.calibrationProgram?.requiredDomains);
  for (const domainRef of REQUIRED_CALIBRATION_DOMAINS) {
    addReason(reasons, !requiredDomains.includes(domainRef), `required_domain_missing:${domainRef}`);
  }
  for (const domainRef of requiredDomains) {
    addReason(reasons, !REQUIRED_CALIBRATION_DOMAINS.includes(domainRef), `required_domain_unsupported:${domainRef}`);
  }

  const coveredDomains = sortedTextList(
    (Array.isArray(input?.readinessControls?.domainEvidence) ? input.readinessControls.domainEvidence : [])
      .filter((entry) => VERIFIED_DOMAIN_STATUSES.has(entry?.status) && isDigest(entry?.evidenceHash))
      .map((entry) => entry.domainRef),
  );
  for (const domainRef of REQUIRED_CALIBRATION_DOMAINS) {
    addReason(reasons, !coveredDomains.includes(domainRef), `domain_evidence_missing:${domainRef}`);
  }
  return { coveredDomains, requiredDomains };
}

function evaluateCalibrationProgram(input, reasons) {
  const program = input?.calibrationProgram;
  addReason(reasons, !hasText(program?.programRef), 'calibration_program_ref_absent');
  addReason(reasons, !hasText(program?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(program?.siteRef), 'site_ref_absent');
  addReason(reasons, !ACTIVE_PROGRAM_STATUSES.has(program?.status), 'calibration_program_not_active');
  addReason(reasons, !isDigest(program?.equipmentInventoryHash), 'equipment_inventory_hash_invalid');
  addReason(reasons, !isDigest(program?.calibrationScheduleHash), 'calibration_schedule_hash_invalid');
  addReason(reasons, !isDigest(program?.calibrationSopHash), 'calibration_sop_hash_invalid');
  addReason(reasons, !isDigest(program?.defectQuarantineProcedureHash), 'defect_quarantine_procedure_hash_invalid');
  addReason(reasons, !isDigest(program?.returnToServiceProcedureHash), 'return_to_service_procedure_hash_invalid');
  addReason(reasons, hlcTuple(program?.assessedAtHlc) === null, 'assessment_time_invalid');
  addReason(reasons, program?.metadataOnly !== true, 'program_metadata_only_attestation_absent');
  addReason(reasons, program?.protectedContentExcluded !== true, 'program_protected_content_boundary_absent');
  addReason(reasons, program?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function recordsByRef(records, key) {
  const byRef = new Map();
  for (const record of records) {
    if (hasText(record?.[key])) {
      byRef.set(record[key], record);
    }
  }
  return byRef;
}

function defectRecordsByEquipment(records) {
  const byEquipment = new Map();
  for (const record of records) {
    if (hasText(record?.equipmentRef)) {
      const list = byEquipment.get(record.equipmentRef) ?? [];
      list.push(record);
      byEquipment.set(record.equipmentRef, list);
    }
  }
  return byEquipment;
}

function evaluateCalibrationEvent(event, equipment, assessedAtHlc, reasons) {
  const ref = hasText(event?.eventRef) ? event.eventRef : 'unknown';
  addReason(reasons, !hasText(event?.eventRef), 'calibration_event_ref_absent');
  addReason(reasons, !hasText(event?.equipmentRef), `calibration_event_equipment_ref_absent:${ref}`);
  addReason(reasons, event?.equipmentRef !== equipment?.equipmentRef, `calibration_event_equipment_mismatch:${ref}`);
  addReason(reasons, !CALIBRATION_EVENT_RESULTS.has(event?.result), `calibration_event_not_passed:${ref}`);
  addReason(reasons, !hasText(event?.performedByDid), `calibration_event_performer_absent:${ref}`);
  addReason(reasons, !isDigest(event?.calibrationEvidenceHash), `calibration_event_evidence_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.standardTraceabilityHash), `calibration_event_traceability_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(event?.certificateHash), `calibration_event_certificate_hash_invalid:${ref}`);
  addReason(reasons, !hlcAfterOrEqual(event?.performedAtHlc, equipment?.lastCalibrationAtHlc), `calibration_event_before_recorded_last:${ref}`);
  addReason(reasons, !hlcBeforeOrEqual(event?.performedAtHlc, assessedAtHlc), `calibration_event_after_assessment:${ref}`);
  addReason(reasons, !hlcEqual(event?.nextDueAtHlc, equipment?.nextCalibrationDueHlc), `calibration_event_next_due_mismatch:${ref}`);
  addReason(reasons, event?.standardTraceabilityHash !== equipment?.calibrationStandardTraceabilityHash, `calibration_event_traceability_mismatch:${ref}`);
  addReason(reasons, event?.metadataOnly !== true, `calibration_event_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, event?.protectedContentExcluded !== true, `calibration_event_protected_content_boundary_absent:${ref}`);
}

function evaluateCheckRecord(record, equipment, assessedAtHlc, reasons) {
  const ref = hasText(record?.checkRef) ? record.checkRef : 'unknown';
  addReason(reasons, !hasText(record?.checkRef), 'check_record_ref_absent');
  addReason(reasons, !hasText(record?.equipmentRef), `check_record_equipment_ref_absent:${ref}`);
  addReason(reasons, record?.equipmentRef !== equipment?.equipmentRef, `check_record_equipment_mismatch:${ref}`);
  addReason(reasons, !CHECK_RESULTS.has(record?.result), `check_record_not_passed:${ref}`);
  addReason(reasons, !hasText(record?.checkedByDid), `check_record_actor_absent:${ref}`);
  addReason(reasons, !isDigest(record?.evidenceHash), `check_record_evidence_hash_invalid:${ref}`);
  addReason(reasons, !hlcAfterOrEqual(record?.checkedAtHlc, equipment?.lastCalibrationAtHlc), `check_record_before_last_calibration:${ref}`);
  addReason(reasons, !hlcBeforeOrEqual(record?.checkedAtHlc, assessedAtHlc), `check_record_after_assessment:${ref}`);
  addReason(reasons, record?.metadataOnly !== true, `check_record_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, record?.protectedContentExcluded !== true, `check_record_protected_content_boundary_absent:${ref}`);
}

function evaluateDefectQuarantineRecord(record, assessedAtHlc, reasons) {
  const ref = hasText(record?.defectRef) ? record.defectRef : 'unknown';
  addReason(reasons, !hasText(record?.defectRef), 'defect_record_ref_absent');
  addReason(reasons, !hasText(record?.equipmentRef), `defect_record_equipment_ref_absent:${ref}`);
  addReason(reasons, !isDigest(record?.defectEvidenceHash), `defect_record_evidence_hash_invalid:${ref}`);
  addReason(reasons, !hasText(record?.severity), `defect_record_severity_absent:${ref}`);
  addReason(reasons, !QUARANTINE_RECORD_STATUSES.has(record?.quarantineStatus), `quarantine_record_status_invalid:${ref}`);
  addReason(reasons, !hlcBeforeOrEqual(record?.defectOpenedAtHlc, assessedAtHlc), `defect_record_after_assessment:${ref}`);
  addReason(reasons, !hlcAfterOrEqual(record?.quarantinedAtHlc, record?.defectOpenedAtHlc), `quarantine_time_before_defect:${ref}`);
  addReason(reasons, !isDigest(record?.quarantineEvidenceHash), `quarantine_evidence_hash_invalid:${ref}`);

  if (record?.quarantineStatus === 'released') {
    addReason(reasons, record?.returnToServiceApproved !== true, `return_to_service_not_approved:${ref}`);
    addReason(reasons, !hasText(record?.returnToServiceApprovedByDid), `return_to_service_approver_absent:${ref}`);
    addReason(reasons, !isDigest(record?.returnToServiceEvidenceHash), `return_to_service_evidence_hash_invalid:${ref}`);
    addReason(reasons, !hlcAfterOrEqual(record?.returnedToServiceAtHlc, record?.quarantinedAtHlc), `return_to_service_before_quarantine:${ref}`);
    addReason(reasons, !hlcBeforeOrEqual(record?.returnedToServiceAtHlc, assessedAtHlc), `return_to_service_after_assessment:${ref}`);
  }

  addReason(reasons, record?.metadataOnly !== true, `defect_record_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, record?.protectedContentExcluded !== true, `defect_record_protected_content_boundary_absent:${ref}`);
}

function latestDefectRecordForEquipment(defectRecords, equipmentRef) {
  const records = defectRecords.get(equipmentRef) ?? [];
  return records.find((record) => hasText(record?.defectRef)) ?? null;
}

function evaluateEquipmentRecord(equipment, context, reasons) {
  const ref = hasText(equipment?.equipmentRef) ? equipment.equipmentRef : 'unknown';
  addReason(reasons, !hasText(equipment?.equipmentRef), 'equipment_ref_absent');
  addReason(reasons, !hasText(equipment?.equipmentType), `equipment_type_absent:${ref}`);
  addReason(reasons, !hasText(equipment?.manufacturerRef), `equipment_manufacturer_absent:${ref}`);
  addReason(reasons, !isDigest(equipment?.serialNumberHash), `equipment_serial_hash_invalid:${ref}`);
  addReason(reasons, !hasText(equipment?.protocolRef), `equipment_protocol_absent:${ref}`);
  addReason(reasons, !hasText(equipment?.siteRef), `equipment_site_absent:${ref}`);
  addReason(reasons, !hasText(equipment?.locationRef), `equipment_location_absent:${ref}`);
  addReason(reasons, !ACTIVE_EQUIPMENT_STATUSES.has(equipment?.status), `equipment_status_inactive:${ref}`);
  addReason(reasons, !isDigest(equipment?.maintenanceRecordHash), `equipment_maintenance_record_hash_invalid:${ref}`);
  addReason(reasons, equipment?.metadataOnly !== true, `equipment_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, equipment?.protectedContentExcluded !== true, `equipment_protected_content_boundary_absent:${ref}`);

  if (equipment?.calibrationRequired === true) {
    addReason(reasons, !positiveInteger(equipment?.calibrationFrequencyDays), `equipment_calibration_frequency_invalid:${ref}`);
    addReason(reasons, !hasText(equipment?.calibrationOwnerDid), `equipment_calibration_owner_absent:${ref}`);
    addReason(reasons, !isDigest(equipment?.calibrationStandardTraceabilityHash), `equipment_calibration_traceability_hash_invalid:${ref}`);
    addReason(reasons, hlcTuple(equipment?.lastCalibrationAtHlc) === null, `equipment_last_calibration_time_invalid:${ref}`);
    addReason(reasons, !hlcAfter(equipment?.nextCalibrationDueHlc, context.assessedAtHlc), `equipment_calibration_due_or_invalid:${ref}`);
    addReason(reasons, !hlcAfterOrEqual(equipment?.nextCalibrationDueHlc, equipment?.lastCalibrationAtHlc), `equipment_calibration_window_invalid:${ref}`);
    addReason(reasons, !hasText(equipment?.currentCalibrationEventRef), `equipment_calibration_event_ref_absent:${ref}`);

    const event = context.calibrationEventsByRef.get(equipment?.currentCalibrationEventRef);
    addReason(reasons, event === undefined, `equipment_calibration_event_missing:${ref}`);
    if (event !== undefined) {
      evaluateCalibrationEvent(event, equipment, context.assessedAtHlc, reasons);
    }
  } else {
    addReason(reasons, equipment?.calibrationRequired !== false, `equipment_calibration_requirement_invalid:${ref}`);
  }

  if (equipment?.checkBeforeUseRequired === true) {
    addReason(reasons, !hasText(equipment?.currentCheckRecordRef), `equipment_check_record_ref_absent:${ref}`);
    const checkRecord = context.checkRecordsByRef.get(equipment?.currentCheckRecordRef);
    addReason(reasons, checkRecord === undefined, `equipment_check_record_missing:${ref}`);
    if (checkRecord !== undefined) {
      evaluateCheckRecord(checkRecord, equipment, context.assessedAtHlc, reasons);
    }
  } else {
    addReason(reasons, equipment?.checkBeforeUseRequired !== false, `equipment_check_requirement_invalid:${ref}`);
  }

  const defectRecord = latestDefectRecordForEquipment(context.defectRecordsByEquipment, equipment?.equipmentRef);
  addReason(reasons, !FIT_EQUIPMENT_STATUSES.has(equipment?.defectStatus), `equipment_not_fit_for_use:${ref}`);
  addReason(
    reasons,
    (!FIT_EQUIPMENT_STATUSES.has(equipment?.defectStatus) || !CLEAR_QUARANTINE_STATUSES.has(equipment?.quarantineStatus)) &&
      defectRecord === null,
    `equipment_defect_record_missing:${ref}`,
  );
  addReason(
    reasons,
    !CLEAR_QUARANTINE_STATUSES.has(equipment?.quarantineStatus) &&
      (defectRecord === null || defectRecord.quarantineStatus !== 'released' || defectRecord.returnToServiceApproved !== true),
    `equipment_quarantined_without_release:${ref}`,
  );
}

function evaluateEquipmentRecords(input, context, reasons) {
  const equipmentRecords = Array.isArray(input?.equipmentRecords) ? input.equipmentRecords : [];
  addReason(reasons, equipmentRecords.length === 0, 'equipment_record_list_absent');
  for (const equipment of equipmentRecords) {
    evaluateEquipmentRecord(equipment, context, reasons);
  }
  return equipmentRecords;
}

function evaluateUnreferencedOperationalRecords(input, assessedAtHlc, reasons) {
  const defectRecords = Array.isArray(input?.defectQuarantineRecords) ? input.defectQuarantineRecords : [];
  for (const record of defectRecords) {
    evaluateDefectQuarantineRecord(record, assessedAtHlc, reasons);
  }
}

function evaluateReadinessControls(input, reasons) {
  const controls = input?.readinessControls;
  addReason(reasons, !nonNegativeInteger(controls?.openDefectCount), 'open_defect_count_invalid');
  addReason(reasons, Number.isSafeInteger(controls?.openDefectCount) && controls.openDefectCount > 0, 'open_defect_count_present');
  addReason(reasons, !nonNegativeInteger(controls?.quarantinedEquipmentCount), 'quarantined_equipment_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.quarantinedEquipmentCount) && controls.quarantinedEquipmentCount > 0,
    'quarantined_equipment_count_present',
  );
  addReason(reasons, controls?.allRequiredEquipmentTraceable !== true, 'equipment_traceability_attestation_absent');
  addReason(reasons, controls?.allCurrentUseBlockedForDefects !== true, 'defective_equipment_use_block_attestation_absent');
  addReason(reasons, !isDigest(controls?.maintenanceReviewHash), 'maintenance_review_hash_invalid');
  addReason(reasons, !isDigest(controls?.inventoryReconciliationHash), 'inventory_reconciliation_hash_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_only_attestation_absent');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_content_boundary_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'reviewer_absent');
  addReason(reasons, !hasText(review?.facilityManagerDid), 'facility_manager_absent');
  addReason(reasons, !hasText(review?.biomedicalReviewerDid), 'biomedical_reviewer_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'review_decision_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.calibrationProgram?.assessedAtHlc), 'review_time_not_after_assessment');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'review_evidence_bundle_hash_invalid');

  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function readinessId(input) {
  return `cmecal_${sha256Hex({
    equipmentRefs: sortedTextList((Array.isArray(input?.equipmentRecords) ? input.equipmentRecords : []).map((entry) => entry?.equipmentRef)),
    programRef: input?.calibrationProgram?.programRef ?? null,
    protocolRef: input?.calibrationProgram?.protocolRef ?? null,
    siteRef: input?.calibrationProgram?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function countEquipment(input, predicate) {
  return (Array.isArray(input?.equipmentRecords) ? input.equipmentRecords : []).filter(predicate).length;
}

function buildCalibrationReadiness(input, domainState, uniqueReasons) {
  const equipmentRecords = Array.isArray(input?.equipmentRecords) ? input.equipmentRecords : [];
  return {
    schema: 'cybermedica.equipment_calibration_readiness_summary.v1',
    readinessId: readinessId(input),
    programRef: input?.calibrationProgram?.programRef ?? null,
    protocolRef: input?.calibrationProgram?.protocolRef ?? null,
    siteRef: input?.calibrationProgram?.siteRef ?? null,
    readinessStatus: uniqueReasons.length === 0 ? 'ready' : 'blocked',
    equipmentCount: equipmentRecords.length,
    calibrationRequiredCount: countEquipment(input, (entry) => entry?.calibrationRequired === true),
    checkBeforeUseRequiredCount: countEquipment(input, (entry) => entry?.checkBeforeUseRequired === true),
    openDefectCount: input?.readinessControls?.openDefectCount ?? null,
    quarantinedEquipmentCount: input?.readinessControls?.quarantinedEquipmentCount ?? null,
    requiredDomains: domainState.requiredDomains,
    coveredDomains: domainState.coveredDomains,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createCalibrationReadinessReceipt(input, calibrationReadiness, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'equipment_calibration_readiness',
    artifactVersion: calibrationReadiness.readinessStatus,
    classification: 'equipment_calibration_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['equipment_calibration_metadata', 'equipment_metadata', 'metadata_only'],
    sourceSystem: 'cybermedica.equipment_calibration_readiness',
    tenantId: input.tenantId,
  });
}

export function evaluateEquipmentCalibrationReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateCalibrationProgram(input, reasons);
  const domainState = evaluateRequiredDomains(input, reasons);

  const assessedAtHlc = input?.calibrationProgram?.assessedAtHlc;
  const calibrationEvents = Array.isArray(input?.calibrationEvents) ? input.calibrationEvents : [];
  const checkRecords = Array.isArray(input?.checkBeforeUseRecords) ? input.checkBeforeUseRecords : [];
  const defectRecords = Array.isArray(input?.defectQuarantineRecords) ? input.defectQuarantineRecords : [];
  addReason(reasons, calibrationEvents.length === 0, 'calibration_event_list_absent');
  addReason(reasons, checkRecords.length === 0, 'check_record_list_absent');
  addReason(reasons, !Array.isArray(input?.defectQuarantineRecords), 'defect_quarantine_record_list_absent');

  const context = {
    assessedAtHlc,
    calibrationEventsByRef: recordsByRef(calibrationEvents, 'eventRef'),
    checkRecordsByRef: recordsByRef(checkRecords, 'checkRef'),
    defectRecordsByEquipment: defectRecordsByEquipment(defectRecords),
  };

  evaluateUnreferencedOperationalRecords(input, assessedAtHlc, reasons);
  evaluateEquipmentRecords(input, context, reasons);
  evaluateReadinessControls(input, reasons);
  evaluateHumanReview(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const calibrationReadiness = buildCalibrationReadiness(input, domainState, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: EQUIPMENT_CALIBRATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      calibrationReadiness,
      receipt: null,
    };
  }

  const artifactHash = sha256Hex({
    actorDid: input.actor.did,
    calibrationEventRefs: sortedTextList(calibrationEvents.map((entry) => entry.eventRef)),
    checkRecordRefs: sortedTextList(checkRecords.map((entry) => entry.checkRef)),
    coveredDomains: calibrationReadiness.coveredDomains,
    decisionForumReceipt: input.humanReview.decisionForum.workflowReceiptId,
    equipmentRefs: sortedTextList(input.equipmentRecords.map((entry) => entry.equipmentRef)),
    maintenanceReviewHash: input.readinessControls.maintenanceReviewHash,
    programRef: input.calibrationProgram.programRef,
    readinessId: calibrationReadiness.readinessId,
    tenantId: input.tenantId,
  });
  const receipt = createCalibrationReadinessReceipt(input, calibrationReadiness, artifactHash);

  return {
    schema: EQUIPMENT_CALIBRATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    calibrationReadiness,
    receipt,
  };
}
