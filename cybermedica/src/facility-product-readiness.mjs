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

const APPROVED_FACILITY_STATUSES = new Set(['approved']);
const READY_FACILITY_STATUSES = new Set(['ready']);
const QUALIFIED_INFRASTRUCTURE_STATUSES = new Set(['qualified', 'verified']);
const VERIFIED_EVIDENCE_STATUSES = new Set(['verified', 'approved']);
const FIT_EQUIPMENT_STATUSES = new Set(['fit_for_use']);
const CLEAR_QUARANTINE_STATUSES = new Set(['not_quarantined']);

const RAW_FACILITY_PRODUCT_FIELDS = new Set([
  'batchserialnumber',
  'equipmentrawlog',
  'facilitynarrative',
  'participantadministrationrecord',
  'productaccountabilitynarrative',
  'rawbatchserial',
  'rawequipmentrecord',
  'rawfacilityassessment',
  'rawfacilitycontent',
  'rawmaintenancebody',
  'rawproduct',
  'rawproductaccountability',
  'rawproductrecord',
  'rawserialnumber',
  'serialnumber',
  'sourcedocumentbody',
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
  return [...new Set(values)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawFacilityProductText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawFacilityProductText(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_FACILITY_PRODUCT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw facility equipment or product content field is not allowed at ${path}.${key}`);
    }
    assertNoRawFacilityProductText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawFacilityProductText(input ?? {});
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
    !hasAuthorityPermission(input?.authority, 'manage_facility_readiness') &&
      !hasAuthorityPermission(input?.authority, 'govern') &&
      !hasAuthorityPermission(input?.authority, 'write'),
    'facility_product_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evidenceRefsComplete(entries, idKey, statusSet) {
  return (
    Array.isArray(entries) &&
    entries.length > 0 &&
    entries.every((entry) => hasText(entry?.[idKey]) && statusSet.has(entry?.status) && isDigest(entry?.evidenceHash))
  );
}

function evaluateFacility(facility, reasons) {
  addReason(reasons, !hasText(facility?.facilityRef), 'facility_ref_absent');
  addReason(reasons, !hasText(facility?.locationRef), 'facility_location_absent');
  addReason(reasons, !hasText(facility?.protocolRef), 'facility_protocol_absent');
  addReason(reasons, !READY_FACILITY_STATUSES.has(facility?.readinessStatus), 'facility_not_ready');
  addReason(reasons, !APPROVED_FACILITY_STATUSES.has(facility?.approvalStatus), 'facility_not_approved');
  addReason(reasons, !isDigest(facility?.trialSpecificRequirementsHash), 'facility_trial_requirements_hash_invalid');
  addReason(reasons, !isDigest(facility?.workEnvironmentAssessmentHash), 'work_environment_assessment_hash_invalid');
  addReason(reasons, !isDigest(facility?.participantEnvironmentAssessmentHash), 'participant_environment_assessment_hash_invalid');
  addReason(reasons, !isDigest(facility?.staffWellbeingAssessmentHash), 'staff_wellbeing_assessment_hash_invalid');
  addReason(reasons, !isDigest(facility?.healthSafetyAssessmentHash), 'health_safety_assessment_hash_invalid');
  addReason(reasons, !isDigest(facility?.accessibilityAssessmentHash), 'accessibility_assessment_hash_invalid');
  addReason(reasons, !isDigest(facility?.maintenanceProgramHash), 'maintenance_program_hash_invalid');
  addReason(reasons, !isDigest(facility?.monitoringEvidenceHash), 'facility_monitoring_evidence_hash_invalid');
  addReason(reasons, !evidenceRefsComplete(facility?.utilityEvidence, 'utility', VERIFIED_EVIDENCE_STATUSES), 'facility_utility_evidence_incomplete');
  addReason(reasons, !evidenceRefsComplete(facility?.storageEvidence, 'storage', VERIFIED_EVIDENCE_STATUSES), 'facility_storage_evidence_incomplete');
  addReason(reasons, !evidenceRefsComplete(facility?.securityEvidence, 'control', VERIFIED_EVIDENCE_STATUSES), 'facility_security_evidence_incomplete');
  addReason(reasons, !evidenceRefsComplete(facility?.privacyEvidence, 'control', VERIFIED_EVIDENCE_STATUSES), 'facility_privacy_evidence_incomplete');

  const infrastructure = Array.isArray(facility?.infrastructure) ? facility.infrastructure : [];
  addReason(reasons, infrastructure.length === 0, 'facility_infrastructure_absent');
  addReason(
    reasons,
    infrastructure.some(
      (item) => !hasText(item?.infrastructureRef) || !QUALIFIED_INFRASTRUCTURE_STATUSES.has(item?.status) || !isDigest(item?.evidenceHash),
    ),
    'facility_infrastructure_not_qualified',
  );

  const gaps = Array.isArray(facility?.gapList) ? facility.gapList : [];
  addReason(reasons, !Array.isArray(facility?.gapList), 'facility_gap_list_absent');
  for (const gap of gaps) {
    addReason(reasons, !hasText(gap?.gapRef), 'facility_gap_ref_absent');
    addReason(reasons, !hasText(gap?.severity), 'facility_gap_severity_absent');
    addReason(reasons, !isDigest(gap?.mitigationEvidenceHash), 'facility_gap_mitigation_absent');
    addReason(reasons, !hasText(gap?.ownerDid), 'facility_gap_owner_absent');
    addReason(reasons, hlcTuple(gap?.targetCloseHlc) === null, 'facility_gap_target_close_invalid');
  }

  return reasons.some((reason) => reason.startsWith('facility_') || reason.includes('environment') || reason.includes('assessment'))
    ? 'blocked'
    : 'ready';
}

function evaluateEquipmentItem(equipment, assessedAtHlc, reasons) {
  addReason(reasons, !hasText(equipment?.equipmentRef), 'equipment_ref_absent');
  addReason(reasons, !hasText(equipment?.equipmentType), 'equipment_type_absent');
  addReason(reasons, !hasText(equipment?.manufacturerRef), 'equipment_manufacturer_absent');
  addReason(reasons, !isDigest(equipment?.serialNumberHash), 'equipment_serial_hash_invalid');
  addReason(reasons, !hasText(equipment?.locationRef), 'equipment_location_absent');
  addReason(reasons, !hasText(equipment?.protocolRef), 'equipment_protocol_absent');
  addReason(reasons, !isDigest(equipment?.maintenanceRecordHash), 'equipment_maintenance_record_hash_invalid');
  addReason(reasons, !FIT_EQUIPMENT_STATUSES.has(equipment?.defectStatus), 'equipment_not_fit_for_use');

  const returnApproval = equipment?.returnToServiceApproval;
  const quarantinedWithoutApproval =
    !CLEAR_QUARANTINE_STATUSES.has(equipment?.quarantineStatus) &&
    (returnApproval?.approved !== true || !hasText(returnApproval?.approvedByDid) || !isDigest(returnApproval?.approvalEvidenceHash));
  addReason(reasons, quarantinedWithoutApproval, 'equipment_quarantined_without_return_to_service');

  if (equipment?.calibrationRequired === true) {
    addReason(reasons, !Number.isSafeInteger(equipment?.calibrationFrequencyDays) || equipment.calibrationFrequencyDays <= 0, 'equipment_calibration_frequency_invalid');
    addReason(reasons, !hasText(equipment?.calibrationResponsibleDid), 'equipment_calibration_responsible_absent');
    addReason(reasons, !isDigest(equipment?.calibrationStandardTraceabilityHash), 'equipment_calibration_traceability_hash_invalid');
    addReason(reasons, hlcTuple(equipment?.lastCalibrationAtHlc) === null, 'equipment_last_calibration_time_invalid');
    addReason(reasons, !hlcAfter(equipment?.nextCalibrationDueHlc, assessedAtHlc), 'equipment_calibration_due_or_invalid');
    addReason(reasons, !hlcAfterOrEqual(equipment?.nextCalibrationDueHlc, equipment?.lastCalibrationAtHlc), 'equipment_calibration_window_invalid');
    addReason(reasons, !isDigest(equipment?.calibrationEvidenceHash), 'equipment_calibration_evidence_hash_invalid');
  } else {
    addReason(reasons, equipment?.calibrationRequired !== false, 'equipment_calibration_requirement_invalid');
  }

  if (equipment?.checkBeforeUseRequired === true) {
    addReason(reasons, !isDigest(equipment?.checkBeforeUseEvidenceHash), 'equipment_check_before_use_evidence_absent');
  } else {
    addReason(reasons, equipment?.checkBeforeUseRequired !== false, 'equipment_check_before_use_requirement_invalid');
  }
}

function evaluateEquipment(equipment, assessedAtHlc, reasons) {
  const equipmentList = Array.isArray(equipment) ? equipment : [];
  addReason(reasons, equipmentList.length === 0, 'equipment_list_absent');
  for (const item of equipmentList) {
    evaluateEquipmentItem(item, assessedAtHlc, reasons);
  }
  return reasons.some((reason) => reason.startsWith('equipment_')) ? 'blocked' : 'ready';
}

function evaluateProductItem(product, assessedAtHlc, reasons) {
  addReason(reasons, !hasText(product?.productRef), 'product_ref_absent');
  addReason(reasons, !hasText(product?.protocolRef), 'product_protocol_absent');
  addReason(reasons, !hasText(product?.sponsorRef), 'product_sponsor_absent');
  addReason(reasons, !hasText(product?.productType), 'product_type_absent');
  addReason(reasons, !isDigest(product?.batchSerialHash), 'product_batch_hash_invalid');
  addReason(reasons, !hlcAfter(product?.expiresAtHlc, assessedAtHlc), 'product_expired_or_expiration_time_invalid');
  addReason(reasons, !isDigest(product?.receiptRecordHash), 'product_receipt_record_hash_invalid');
  addReason(reasons, !isDigest(product?.storageRequirementHash), 'product_storage_requirement_hash_invalid');
  addReason(reasons, !hasText(product?.storageLocationRef), 'product_storage_location_absent');
  addReason(reasons, !isDigest(product?.temperatureControlEvidenceHash), 'product_temperature_control_evidence_hash_invalid');
  addReason(reasons, sortedTextList(product?.accessPermissionRefs).length === 0, 'product_access_permissions_absent');
  addReason(reasons, !hasText(product?.dispensingResponsibleDid), 'product_dispensing_responsible_absent');
  addReason(reasons, !hasText(product?.blindingResponsibleDid), 'product_blinding_responsible_absent');
  addReason(reasons, !isDigest(product?.transportRequirementHash), 'product_transport_requirement_hash_invalid');
  addReason(reasons, !isDigest(product?.transitIntegrityControlHash), 'product_transit_integrity_hash_invalid');
  addReason(reasons, !isDigest(product?.uniqueCodeNumberLinkageHash), 'product_unique_code_linkage_hash_invalid');
  addReason(reasons, !isDigest(product?.administrationRecordHash), 'product_administration_record_hash_invalid');
  addReason(reasons, !isDigest(product?.stockReconciliationHash), 'product_stock_reconciliation_hash_invalid');
  addReason(reasons, !isDigest(product?.expiredProductManagementHash), 'product_expired_management_hash_invalid');
  addReason(reasons, !isDigest(product?.damagedContaminatedManagementHash), 'product_damaged_management_hash_invalid');
  addReason(reasons, !isDigest(product?.returnDisposalRecordHash), 'product_return_disposal_hash_invalid');

  const quantityFields = ['quantityReceived', 'quantityDispensed', 'quantityReturned', 'quantityDisposed', 'currentStock'];
  const invalidQuantity = quantityFields.some((field) => !Number.isSafeInteger(product?.[field]) || product[field] < 0);
  addReason(reasons, invalidQuantity, 'product_quantity_invalid');

  let accountabilityDefect = false;
  if (!invalidQuantity) {
    const expectedStock = product.quantityReceived - product.quantityDispensed - product.quantityReturned - product.quantityDisposed;
    accountabilityDefect = expectedStock !== product.currentStock;
    addReason(reasons, accountabilityDefect, 'product_stock_reconciliation_mismatch');
  }

  const expired = !hlcAfter(product?.expiresAtHlc, assessedAtHlc);
  addReason(reasons, (expired || accountabilityDefect) && !hasText(product?.nonconformityRef), 'product_nonconformity_linkage_absent');
}

function evaluateProducts(products, assessedAtHlc, reasons) {
  const productList = Array.isArray(products) ? products : [];
  addReason(reasons, productList.length === 0, 'product_list_absent');
  for (const item of productList) {
    evaluateProductItem(item, assessedAtHlc, reasons);
  }
  return reasons.some((reason) => reason.startsWith('product_')) ? 'blocked' : 'ready';
}

function evaluateLaunchGovernance(input, reasons) {
  const launch = input?.launchReadiness;
  addReason(reasons, launch?.facilityReadinessRequired !== true, 'launch_facility_readiness_check_absent');
  addReason(reasons, launch?.equipmentReadinessRequired !== true, 'launch_equipment_readiness_check_absent');
  addReason(reasons, launch?.productHandlingReadinessRequired !== true, 'launch_product_handling_check_absent');
  addReason(reasons, !hasText(launch?.authorizedLaunchCheckRef), 'launch_check_ref_absent');
  addReason(reasons, hlcTuple(launch?.readinessAssessedAtHlc) === null, 'launch_readiness_assessment_time_invalid');

  const forum = input?.review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.qualityReviewerDid), 'quality_reviewer_absent');
  addReason(reasons, !hasText(input?.review?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, !hasText(input?.review?.facilityManagerDid), 'facility_manager_absent');
  addReason(reasons, !hasText(input?.review?.productManagerDid), 'product_manager_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function readinessId(input) {
  return `cmfpr_${sha256Hex({
    equipmentRefs: sortedTextList((Array.isArray(input?.equipment) ? input.equipment : []).map((item) => item?.equipmentRef).filter(hasText)),
    facilityRef: input?.facility?.facilityRef ?? null,
    productRefs: sortedTextList((Array.isArray(input?.products) ? input.products : []).map((item) => item?.productRef).filter(hasText)),
    protocolRef: input?.facility?.protocolRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function requiredLaunchChecks(input) {
  const checks = [];
  if (input?.launchReadiness?.equipmentReadinessRequired === true) {
    checks.push('equipment_readiness');
  }
  if (input?.launchReadiness?.facilityReadinessRequired === true) {
    checks.push('facility_readiness');
  }
  if (input?.launchReadiness?.productHandlingReadinessRequired === true) {
    checks.push('product_handling_readiness');
  }
  return checks.sort();
}

function buildReadinessSummary(input, statuses) {
  const equipmentList = Array.isArray(input?.equipment) ? input.equipment : [];
  const productList = Array.isArray(input?.products) ? input.products : [];
  const gapList = Array.isArray(input?.facility?.gapList) ? input.facility.gapList : [];
  const readinessStatus =
    statuses.facilityStatus === 'ready' && statuses.equipmentStatus === 'ready' && statuses.productStatus === 'ready'
      ? 'ready_for_launch'
      : 'not_ready';

  return {
    schema: 'cybermedica.facility_product_readiness_summary.v1',
    readinessId: readinessId(input),
    facilityRef: input?.facility?.facilityRef ?? null,
    protocolRef: input?.facility?.protocolRef ?? null,
    readinessStatus,
    facilityStatus: statuses.facilityStatus,
    equipmentStatus: statuses.equipmentStatus,
    productStatus: statuses.productStatus,
    openGapCount: gapList.length,
    equipmentCount: equipmentList.length,
    productCount: productList.length,
    requiredLaunchChecks: requiredLaunchChecks(input),
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createReadinessReceipt(input, readiness, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'facility_equipment_product_readiness',
    artifactVersion: readiness.readinessStatus,
    classification: 'launch_readiness_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.launchReadiness.readinessAssessedAtHlc,
    sensitivityTags: ['facility_metadata', 'equipment_metadata', 'metadata_only', 'product_accountability_metadata'],
    sourceSystem: 'cybermedica.facility_product_readiness',
    tenantId: input.tenantId,
  });
}

export function evaluateFacilityProductReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateLaunchGovernance(input, reasons);

  const assessedAtHlc = input?.launchReadiness?.readinessAssessedAtHlc;
  const facilityStatus = evaluateFacility(input?.facility, reasons);
  const equipmentStatus = evaluateEquipment(input?.equipment, assessedAtHlc, reasons);
  const productStatus = evaluateProducts(input?.products, assessedAtHlc, reasons);
  const readiness = buildReadinessSummary(input, { equipmentStatus, facilityStatus, productStatus });
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.facility_product_readiness.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      readiness,
      receipt: null,
    };
  }

  const recordHash = sha256Hex({
    actorDid: input.actor.did,
    decisionForumReceipt: input.review.decisionForum.workflowReceiptId,
    equipmentRefs: sortedTextList(input.equipment.map((item) => item.equipmentRef)),
    facilityRef: input.facility.facilityRef,
    facilityStatus,
    monitoringEvidenceHash: input.facility.monitoringEvidenceHash,
    productRefs: sortedTextList(input.products.map((item) => item.productRef)),
    productStatus,
    readinessId: readiness.readinessId,
    requiredLaunchChecks: readiness.requiredLaunchChecks,
    tenantId: input.tenantId,
  });
  const receipt = createReadinessReceipt(input, readiness, recordHash);

  return {
    schema: 'cybermedica.facility_product_readiness.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    readiness,
    receipt,
  };
}
