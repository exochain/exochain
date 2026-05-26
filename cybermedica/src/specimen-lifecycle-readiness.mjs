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
const REQUIRED_PERMISSION = 'manage_specimen_lifecycle';
const SPECIMEN_SCHEMA = 'cybermedica.specimen_lifecycle_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.specimen_lifecycle_readiness_decision.v1';

const REQUIRED_SPECIMEN_FAMILIES = Object.freeze([
  'biomarker_blood',
  'pharmacokinetic_sample',
  'safety_laboratory',
  'urine_sample',
]);

const REQUIRED_HANDLING_DOMAINS = Object.freeze([
  'central_lab_receipt',
  'collection_identity_separation',
  'courier_chain_of_custody',
  'processing_time_window',
  'result_reconciliation',
  'temperature_monitoring',
]);

const ACTIVE_PLAN_STATUSES = new Set(['active']);
const READY_KIT_STATUSES = new Set(['ready']);
const VERIFIED_CONTROL_STATUSES = new Set(['verified']);

const RAW_SPECIMEN_FIELDS = new Set([
  'directidentifier',
  'labresultbody',
  'labvalue',
  'participantidentifier',
  'participantname',
  'patientname',
  'rawlabresult',
  'rawpayload',
  'rawresult',
  'rawsample',
  'rawspecimen',
  'rawspecimenlabel',
  'samplelabel',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'specimenlabel',
  'specimennarrative',
  'subjectidentifier',
]);

const SECRET_SPECIMEN_FIELDS = new Set([
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

function assertNoRawSpecimenContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSpecimenContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SPECIMEN_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw specimen or laboratory result content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SPECIMEN_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`specimen lifecycle secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSpecimenContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSpecimenContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(isDigest))].sort() : [];
}

function safeNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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
    'specimen_lifecycle_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSpecimenPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'specimen_plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !ACTIVE_PLAN_STATUSES.has(plan?.status), 'specimen_plan_not_active');
  addReason(reasons, !isDigest(plan?.collectionManualHash), 'collection_manual_hash_invalid');
  addReason(reasons, !isDigest(plan?.labManualHash), 'lab_manual_hash_invalid');
  addReason(reasons, !isDigest(plan?.processingProcedureHash), 'processing_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.shippingProcedureHash), 'shipping_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.resultReviewProcedureHash), 'result_review_procedure_hash_invalid');
  addReason(reasons, !hasText(plan?.consentMaterialRef), 'consent_material_ref_absent');
  addReason(reasons, hlcTuple(plan?.reviewedAtHlc) === null, 'specimen_plan_review_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'specimen_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'specimen_plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  const requiredFamilies = sortedTextList(plan?.requiredSpecimenFamilies);
  evaluateRequiredSet(
    requiredFamilies,
    REQUIRED_SPECIMEN_FAMILIES,
    'specimen_plan_family_missing',
    'specimen_plan_family_unsupported',
    reasons,
  );

  return [...REQUIRED_SPECIMEN_FAMILIES];
}

function kitIdentity(kit) {
  return hasText(kit?.kitRef) ? kit.kitRef : 'unclassified_kit';
}

function evaluateCollectionKit(kit, planReviewedAtHlc, reasons) {
  const kitRef = kitIdentity(kit);
  addReason(reasons, !hasText(kit?.kitRef), 'kit_ref_absent');
  addReason(reasons, !REQUIRED_SPECIMEN_FAMILIES.includes(kit?.specimenFamily), `kit_specimen_family_invalid:${kitRef}`);
  addReason(reasons, !READY_KIT_STATUSES.has(kit?.status), `kit_not_ready:${kitRef}`);
  addReason(reasons, !isDigest(kit?.kitInventoryHash), `kit_inventory_hash_invalid:${kitRef}`);
  addReason(reasons, !isDigest(kit?.kitInstructionHash), `kit_instruction_hash_invalid:${kitRef}`);
  addReason(reasons, !isDigest(kit?.consentBoundaryHash), `kit_consent_boundary_hash_invalid:${kitRef}`);
  addReason(reasons, !isDigest(kit?.collectionWindowHash), `kit_collection_window_hash_invalid:${kitRef}`);
  addReason(reasons, !isDigest(kit?.aliquotPlanHash), `kit_aliquot_plan_hash_invalid:${kitRef}`);
  addReason(reasons, !hasText(kit?.ownerDid), `kit_owner_absent:${kitRef}`);
  addReason(reasons, !hlcAfter(kit?.expiresAtHlc, planReviewedAtHlc), `kit_expired_or_invalid:${kitRef}`);
  addReason(reasons, hlcTuple(kit?.lastReviewedAtHlc) === null, `kit_last_review_time_invalid:${kitRef}`);
  addReason(reasons, !hlcBeforeOrEqual(kit?.lastReviewedAtHlc, planReviewedAtHlc), `kit_last_review_after_plan_review:${kitRef}`);
  addReason(reasons, kit?.metadataOnly !== true, `kit_metadata_boundary_invalid:${kitRef}`);
  addReason(reasons, kit?.protectedContentExcluded !== true, `kit_protected_boundary_invalid:${kitRef}`);

  return {
    kitRef,
    specimenFamily: kit?.specimenFamily,
  };
}

function evaluateCollectionKits(input, requiredFamilies, reasons) {
  const kits = Array.isArray(input?.collectionKits) ? input.collectionKits : [];
  addReason(reasons, kits.length === 0, 'collection_kit_inventory_absent');
  const summaries = kits.map((kit) => evaluateCollectionKit(kit, input?.specimenPlan?.reviewedAtHlc, reasons));
  const covered = sortedTextList(summaries.map((summary) => summary.specimenFamily)).filter((family) =>
    REQUIRED_SPECIMEN_FAMILIES.includes(family),
  );
  for (const family of requiredFamilies) {
    addReason(reasons, !covered.includes(family), `required_specimen_family_missing:${family}`);
  }
  return {
    specimenFamiliesCovered: covered,
    kitRefs: sortedTextList(summaries.map((summary) => summary.kitRef)),
  };
}

function evaluateHandlingControl(control, planReviewedAtHlc, reasons) {
  const domainRef = hasText(control?.domainRef) ? control.domainRef : 'unclassified_handling_domain';
  addReason(reasons, !hasText(control?.domainRef), 'handling_domain_ref_absent');
  addReason(reasons, !REQUIRED_HANDLING_DOMAINS.includes(control?.domainRef), `handling_domain_unsupported:${domainRef}`);
  addReason(reasons, !VERIFIED_CONTROL_STATUSES.has(control?.status), `handling_control_not_verified:${domainRef}`);
  addReason(reasons, !isDigest(control?.evidenceHash), `handling_control_evidence_hash_invalid:${domainRef}`);
  addReason(reasons, !isDigest(control?.custodyDigest), `handling_control_custody_digest_invalid:${domainRef}`);
  addReason(reasons, !hasText(control?.ownerDid), `handling_control_owner_absent:${domainRef}`);
  addReason(reasons, hlcTuple(control?.reviewedAtHlc) === null, `handling_control_review_time_invalid:${domainRef}`);
  addReason(
    reasons,
    hlcTuple(control?.reviewedAtHlc) !== null &&
      hlcTuple(planReviewedAtHlc) !== null &&
      !hlcBeforeOrEqual(control.reviewedAtHlc, planReviewedAtHlc),
    `handling_control_review_after_plan_review:${domainRef}`,
  );
  addReason(reasons, control?.metadataOnly !== true, `handling_control_metadata_boundary_invalid:${domainRef}`);
  addReason(reasons, control?.protectedContentExcluded !== true, `handling_control_protected_boundary_invalid:${domainRef}`);
  return domainRef;
}

function evaluateHandlingControls(input, reasons) {
  const controls = Array.isArray(input?.handlingControls) ? input.handlingControls : [];
  addReason(reasons, controls.length === 0, 'handling_control_inventory_absent');
  const domainsCovered = sortedTextList(controls.map((control) => evaluateHandlingControl(control, input?.specimenPlan?.reviewedAtHlc, reasons))).filter(
    (domainRef) => REQUIRED_HANDLING_DOMAINS.includes(domainRef),
  );
  evaluateRequiredSet(
    domainsCovered,
    REQUIRED_HANDLING_DOMAINS,
    'handling_domain_missing',
    'handling_domain_unsupported',
    reasons,
  );
  return domainsCovered;
}

function evaluateLogistics(logistics, reasons) {
  addReason(reasons, !hasText(logistics?.centralLabVendorReadinessRef), 'central_lab_vendor_readiness_ref_absent');
  addReason(reasons, !hasText(logistics?.logisticsVendorReadinessRef), 'logistics_vendor_readiness_ref_absent');
  addReason(reasons, !hasText(logistics?.pharmacyReadinessRef), 'pharmacy_readiness_ref_absent');
  addReason(reasons, sortedTextList(logistics?.governedIntegrationRefs).length === 0, 'governed_integration_ref_absent');
  addReason(reasons, !isDigest(logistics?.specimenManifestHash), 'specimen_manifest_hash_invalid');
  addReason(reasons, !isDigest(logistics?.shipmentTrackingHash), 'shipment_tracking_hash_invalid');
  addReason(reasons, !isDigest(logistics?.temperatureExcursionRegisterHash), 'temperature_excursion_register_hash_invalid');
  addReason(reasons, !isDigest(logistics?.transferOfCustodyHash), 'transfer_of_custody_hash_invalid');
  addReason(reasons, !isDigest(logistics?.externalLabResultBoundaryHash), 'external_lab_result_boundary_hash_invalid');
  addReason(reasons, logistics?.metadataOnly !== true, 'logistics_metadata_boundary_invalid');
  addReason(reasons, logistics?.protectedContentExcluded !== true, 'logistics_protected_boundary_invalid');
}

function evaluateResultReview(resultReview, planReviewedAtHlc, reasons) {
  addReason(reasons, !hasText(resultReview?.reviewRef), 'result_review_ref_absent');
  addReason(reasons, !hasText(resultReview?.reviewerDid), 'result_review_reviewer_absent');
  addReason(reasons, hlcTuple(resultReview?.reviewedAtHlc) === null, 'result_review_time_invalid');
  addReason(reasons, !hlcAfter(resultReview?.reviewedAtHlc, planReviewedAtHlc), 'result_review_before_plan_review');
  addReason(
    reasons,
    !isDigest(resultReview?.abnormalResultEscalationProcedureHash),
    'abnormal_result_escalation_procedure_hash_invalid',
  );
  addReason(reasons, !isDigest(resultReview?.safetyEventLinkageHash), 'safety_event_linkage_hash_invalid');
  addReason(reasons, !isDigest(resultReview?.sourceDataReconciliationHash), 'source_data_reconciliation_hash_invalid');
  addReason(
    reasons,
    !safeNonNegativeInteger(resultReview?.unresolvedCriticalAbnormalCount),
    'unresolved_critical_abnormal_count_invalid',
  );
  addReason(reasons, !safeNonNegativeInteger(resultReview?.pendingResultCount), 'pending_result_count_invalid');
  addReason(reasons, resultReview?.unresolvedCriticalAbnormalCount > 0, 'unresolved_critical_abnormal_results');
  addReason(reasons, resultReview?.pendingResultCount > 0, 'pending_lab_results_present');
  addReason(reasons, !isDigest(resultReview?.repeatCollectionDecisionHash), 'repeat_collection_decision_hash_invalid');
  addReason(reasons, resultReview?.participantIdentifierSuppressed !== true, 'participant_identifier_suppression_absent');
  addReason(reasons, resultReview?.metadataOnly !== true, 'result_review_metadata_boundary_invalid');
  addReason(reasons, resultReview?.protectedContentExcluded !== true, 'result_review_protected_boundary_invalid');
}

function evaluateDependencyEvidence(evidence, reasons) {
  addReason(reasons, !hasText(evidence?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, !hasText(evidence?.facilityProductReadinessRef), 'facility_product_readiness_ref_absent');
  addReason(reasons, !hasText(evidence?.vendorSubcontractorReadinessRef), 'vendor_subcontractor_readiness_ref_absent');
  addReason(reasons, !hasText(evidence?.consentMaterialsRef), 'consent_materials_ref_absent');
  addReason(
    reasons,
    sortedDigestList(evidence?.evidenceHashes).length === 0,
    'specimen_dependency_evidence_hash_invalid',
  );
  addReason(reasons, evidence?.metadataOnly !== true, 'specimen_dependency_metadata_boundary_invalid');
}

function evaluateHumanGovernance(review, reasons) {
  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function hasReasonWithPrefix(reasons, prefixes) {
  return reasons.some((reason) => prefixes.some((prefix) => reason.startsWith(prefix)));
}

function buildSpecimenLifecycle(input, collectionSummary, handlingDomainsCovered, reasons) {
  const plan = input?.specimenPlan;
  const resultReview = input?.resultReview;
  const material = {
    schema: SPECIMEN_SCHEMA,
    tenantId: input?.tenantId ?? '',
    planRef: plan?.planRef ?? '',
    protocolRef: plan?.protocolRef ?? '',
    siteRef: plan?.siteRef ?? '',
    specimenFamiliesCovered: collectionSummary.specimenFamiliesCovered,
    handlingDomainsCovered,
    collectionKitRefs: collectionSummary.kitRefs,
    centralLabVendorReadinessRef: input?.logistics?.centralLabVendorReadinessRef ?? '',
    logisticsVendorReadinessRef: input?.logistics?.logisticsVendorReadinessRef ?? '',
    resultReviewRef: resultReview?.reviewRef ?? '',
    reviewedAtHlc: plan?.reviewedAtHlc ?? null,
  };
  const permitted = reasons.length === 0;
  const handlingBlocked = hasReasonWithPrefix(reasons, ['handling_', 'collection_', 'kit_', 'required_specimen_family_']);
  const logisticsBlocked = hasReasonWithPrefix(reasons, [
    'central_lab_',
    'external_lab_',
    'governed_integration_',
    'logistics_',
    'pharmacy_',
    'shipment_',
    'specimen_manifest_',
    'temperature_excursion_',
    'transfer_of_custody_',
  ]);
  const resultBlocked = hasReasonWithPrefix(reasons, [
    'abnormal_',
    'pending_',
    'participant_identifier_',
    'repeat_collection_',
    'result_review_',
    'safety_event_',
    'source_data_',
    'unresolved_',
  ]);

  return {
    ...material,
    readinessId: `specimen_lifecycle_${sha256Hex(material).slice(0, 32)}`,
    readinessStatus: permitted ? 'ready_for_specimen_operations' : 'not_ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true,
    kitCount: collectionSummary.kitRefs.length,
    handlingStatus: handlingBlocked ? 'blocked' : 'ready',
    logisticsStatus: logisticsBlocked ? 'blocked' : 'ready',
    resultReviewStatus: resultBlocked ? 'blocked' : 'ready',
    unresolvedCriticalAbnormalCount: safeNonNegativeInteger(resultReview?.unresolvedCriticalAbnormalCount)
      ? resultReview.unresolvedCriticalAbnormalCount
      : 0,
    pendingResultCount: safeNonNegativeInteger(resultReview?.pendingResultCount) ? resultReview.pendingResultCount : 0,
    dependencyRefs: {
      consentMaterialsRef: input?.dependencyEvidence?.consentMaterialsRef ?? '',
      facilityProductReadinessRef: input?.dependencyEvidence?.facilityProductReadinessRef ?? '',
      protocolFeasibilityRef: input?.dependencyEvidence?.protocolFeasibilityRef ?? '',
      vendorSubcontractorReadinessRef: input?.dependencyEvidence?.vendorSubcontractorReadinessRef ?? '',
    },
    decisionForum: {
      decisionId: input?.review?.decisionForum?.decisionId ?? null,
      workflowReceiptId: input?.review?.decisionForum?.workflowReceiptId ?? null,
      verified: input?.review?.decisionForum?.verified === true,
      humanGateVerified: input?.review?.decisionForum?.humanGate?.verified === true,
      quorumStatus: input?.review?.decisionForum?.quorum?.status ?? null,
    },
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createSpecimenLifecycleReceipt(input, specimenLifecycle) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(specimenLifecycle),
    artifactType: 'specimen_lifecycle_readiness',
    artifactVersion: `${input.specimenPlan.planRef}@${input.specimenPlan.reviewedAtHlc.physicalMs}.${input.specimenPlan.reviewedAtHlc.logical}`,
    classification: 'clinical-specimen-metadata-only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.specimenPlan.reviewedAtHlc,
    sensitivityTags: ['clinical_operations', 'metadata_only', 'specimen_lifecycle', 'sponsor_cro_confidential'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateSpecimenLifecycleReadiness(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const requiredFamilies = evaluateSpecimenPlan(input?.specimenPlan, reasons);
  const collectionSummary = evaluateCollectionKits(input, requiredFamilies, reasons);
  const handlingDomainsCovered = evaluateHandlingControls(input, reasons);
  evaluateLogistics(input?.logistics, reasons);
  evaluateResultReview(input?.resultReview, input?.specimenPlan?.reviewedAtHlc, reasons);
  evaluateDependencyEvidence(input?.dependencyEvidence, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const specimenLifecycle = buildSpecimenLifecycle(input, collectionSummary, handlingDomainsCovered, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    specimenLifecycle,
    receipt: permitted ? createSpecimenLifecycleReceipt(input, specimenLifecycle) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
