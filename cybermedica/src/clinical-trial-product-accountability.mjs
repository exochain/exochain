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
const REQUIRED_PERMISSION = 'manage_product_accountability';
const PRODUCT_ACCOUNTABILITY_SCHEMA = 'cybermedica.clinical_trial_product_accountability.v1';

const REQUIRED_ACCOUNTABILITY_DOMAINS = Object.freeze([
  'access_control',
  'blinding_control',
  'dispensing',
  'disposal',
  'expiration_control',
  'receipt',
  'reconciliation',
  'return',
  'stock_control',
  'storage',
]);

const ACTIVE_PLAN_STATUSES = new Set(['active']);
const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const REVIEW_DECISIONS = new Set(['product_accountability_reconciled', 'hold_product_accountability_gap']);
const BLINDING_STATUSES = new Set(['blinded', 'open_label', 'emergency_unblinded']);
const RETURN_DISPOSAL_RECORD_TYPES = new Set(['destruction', 'disposal', 'return_to_sponsor']);

const RAW_PRODUCT_ACCOUNTABILITY_FIELDS = new Set([
  'batchserialnumber',
  'directidentifier',
  'dispensingnote',
  'participantidentifier',
  'participantname',
  'patientname',
  'productaccountabilitynarrative',
  'rawdispensingrecord',
  'rawpayload',
  'rawproduct',
  'rawproductaccountability',
  'rawproductrecord',
  'rawserialnumber',
  'serialnumber',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
]);

const SECRET_PRODUCT_ACCOUNTABILITY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'pharmacysecret',
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

function assertNoRawProductAccountabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawProductAccountabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PRODUCT_ACCOUNTABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw clinical trial product accountability field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PRODUCT_ACCOUNTABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`clinical trial product accountability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawProductAccountabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawProductAccountabilityContent(input ?? {});
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

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
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
    'product_accountability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredDomains(input, reasons) {
  const requiredDomains = sortedTextList(input?.accountabilityPlan?.requiredDomains);
  for (const domainRef of REQUIRED_ACCOUNTABILITY_DOMAINS) {
    addReason(reasons, !requiredDomains.includes(domainRef), `required_domain_missing:${domainRef}`);
  }
  for (const domainRef of requiredDomains) {
    addReason(reasons, !REQUIRED_ACCOUNTABILITY_DOMAINS.includes(domainRef), `required_domain_unsupported:${domainRef}`);
  }

  const coveredDomains = sortedTextList(
    (Array.isArray(input?.accountabilityControls?.domainEvidence) ? input.accountabilityControls.domainEvidence : [])
      .filter((entry) => VERIFIED_DOMAIN_STATUSES.has(entry?.status) && isDigest(entry?.evidenceHash))
      .map((entry) => entry.domainRef),
  );
  for (const domainRef of REQUIRED_ACCOUNTABILITY_DOMAINS) {
    addReason(reasons, !coveredDomains.includes(domainRef), `domain_evidence_missing:${domainRef}`);
  }
  return { coveredDomains, requiredDomains };
}

function evaluateAccountabilityPlan(input, reasons) {
  const plan = input?.accountabilityPlan;
  addReason(reasons, !hasText(plan?.planRef), 'plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !ACTIVE_PLAN_STATUSES.has(plan?.status), 'plan_not_active');
  addReason(reasons, !isDigest(plan?.productAccountabilitySopHash), 'product_accountability_sop_hash_invalid');
  addReason(reasons, !isDigest(plan?.randomizationPlanHash), 'randomization_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.blindingPlanHash), 'blinding_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.accessPolicyHash), 'access_policy_hash_invalid');
  addReason(reasons, !isDigest(plan?.storageProcedureHash), 'storage_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.reconciliationProcedureHash), 'reconciliation_procedure_hash_invalid');
  addReason(reasons, hlcTuple(plan?.assessedAtHlc) === null, 'assessment_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'plan_metadata_only_attestation_absent');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'plan_protected_content_boundary_absent');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateProductLot(product, assessedAtHlc, reasons) {
  const ref = hasText(product?.productRef) ? product.productRef : 'unknown';
  addReason(reasons, !hasText(product?.productRef), 'product_ref_absent');
  addReason(reasons, !hasText(product?.protocolRef), `product_protocol_absent:${ref}`);
  addReason(reasons, !hasText(product?.siteRef), `product_site_absent:${ref}`);
  addReason(reasons, !hasText(product?.sponsorRef), `product_sponsor_absent:${ref}`);
  addReason(reasons, !hasText(product?.productType), `product_type_absent:${ref}`);
  addReason(reasons, !hasText(product?.lotRef), `product_lot_ref_absent:${ref}`);
  addReason(reasons, !isDigest(product?.batchSerialHash), `product_batch_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.receiptRecordHash), `product_receipt_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.storageControlHash), `product_storage_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.temperatureControlHash), `product_temperature_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.accessControlHash), `product_access_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.blindingControlHash), `product_blinding_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(product?.receivedAtHlc) === null, `product_receipt_time_invalid:${ref}`);
  addReason(reasons, !hlcAfter(product?.expirationAtHlc, assessedAtHlc), `product_expired_or_expiration_time_invalid:${ref}`);

  const quantityFields = [
    'quantityReceived',
    'quantityDispensed',
    'quantityReturnedToSponsor',
    'quantityDisposed',
    'quantityOnHand',
  ];
  const invalidQuantity = quantityFields.some((field) => !nonNegativeInteger(product?.[field]));
  addReason(reasons, invalidQuantity, `product_quantity_invalid:${ref}`);

  let reconciliationMismatch = false;
  if (!invalidQuantity) {
    const expectedOnHand =
      product.quantityReceived - product.quantityDispensed - product.quantityReturnedToSponsor - product.quantityDisposed;
    reconciliationMismatch = expectedOnHand !== product.quantityOnHand;
    addReason(reasons, reconciliationMismatch, `product_stock_reconciliation_mismatch:${ref}`);
  }

  const expired = !hlcAfter(product?.expirationAtHlc, assessedAtHlc);
  addReason(reasons, (expired || reconciliationMismatch) && !hasText(product?.nonconformityRef), `product_nonconformity_linkage_absent:${ref}`);
  addReason(reasons, product?.metadataOnly !== true, `product_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, product?.protectedContentExcluded !== true, `product_protected_content_boundary_absent:${ref}`);
}

function productMap(productLots) {
  const byRef = new Map();
  for (const product of productLots) {
    if (hasText(product?.productRef)) {
      byRef.set(product.productRef, product);
    }
  }
  return byRef;
}

function evaluateProductLots(input, reasons) {
  const products = Array.isArray(input?.productLots) ? input.productLots : [];
  addReason(reasons, products.length === 0, 'product_lot_list_absent');
  for (const product of products) {
    evaluateProductLot(product, input?.accountabilityPlan?.assessedAtHlc, reasons);
  }
  return products;
}

function evaluateDispensingRecord(record, productsByRef, assessedAtHlc, reasons) {
  const ref = hasText(record?.dispensingRef) ? record.dispensingRef : 'unknown';
  const product = productsByRef.get(record?.productRef);
  addReason(reasons, !hasText(record?.dispensingRef), 'dispensing_ref_absent');
  addReason(reasons, !hasText(record?.productRef), `dispensing_product_ref_absent:${ref}`);
  addReason(reasons, hasText(record?.productRef) && product === undefined, `dispensing_product_unknown:${record?.productRef}`);
  addReason(reasons, !isDigest(record?.participantCodeHash), `dispensing_participant_code_hash_invalid:${ref}`);
  addReason(reasons, !positiveInteger(record?.quantityDispensed), `dispensing_quantity_invalid:${ref}`);
  addReason(reasons, !hasText(record?.dispensedByDid), `dispensing_actor_absent:${ref}`);
  addReason(reasons, !hasText(record?.witnessDid), `dispensing_witness_absent:${ref}`);
  addReason(reasons, !isDigest(record?.prescriptionOrderHash), `dispensing_order_hash_invalid:${ref}`);
  addReason(reasons, !hasText(record?.visitRef), `dispensing_visit_ref_absent:${ref}`);
  addReason(reasons, !BLINDING_STATUSES.has(record?.blindingStatus), `dispensing_blinding_status_invalid:${ref}`);
  addReason(reasons, record?.blindingStatus === 'emergency_unblinded' && !hasText(record?.unblindedActorDid), `emergency_unblinding_actor_absent:${ref}`);
  addReason(reasons, product !== undefined && !hlcAfter(record?.dispensedAtHlc, product.receivedAtHlc), `dispensing_time_not_after_receipt:${ref}`);
  addReason(reasons, !hlcBeforeOrEqual(record?.dispensedAtHlc, assessedAtHlc), `dispensing_time_after_assessment:${ref}`);
  addReason(reasons, record?.metadataOnly !== true, `dispensing_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, record?.protectedContentExcluded !== true, `dispensing_protected_content_boundary_absent:${ref}`);
}

function evaluateDispensingRecords(input, productsByRef, reasons) {
  const records = Array.isArray(input?.dispensingRecords) ? input.dispensingRecords : [];
  addReason(reasons, records.length === 0, 'dispensing_record_list_absent');
  for (const record of records) {
    evaluateDispensingRecord(record, productsByRef, input?.accountabilityPlan?.assessedAtHlc, reasons);
  }
  return records;
}

function evaluateReturnDisposalRecord(record, productsByRef, reasons) {
  const ref = hasText(record?.recordRef) ? record.recordRef : 'unknown';
  const product = productsByRef.get(record?.productRef);
  addReason(reasons, !hasText(record?.recordRef), 'return_disposal_ref_absent');
  addReason(reasons, !RETURN_DISPOSAL_RECORD_TYPES.has(record?.recordType), `return_disposal_type_invalid:${ref}`);
  addReason(reasons, !hasText(record?.productRef), `return_disposal_product_ref_absent:${ref}`);
  addReason(reasons, hasText(record?.productRef) && product === undefined, `return_disposal_product_unknown:${record?.productRef}`);
  addReason(reasons, !nonNegativeInteger(record?.quantity), `return_disposal_quantity_invalid:${ref}`);
  addReason(reasons, !hasText(record?.recordedByDid), `return_disposal_actor_absent:${ref}`);
  addReason(reasons, !isDigest(record?.evidenceHash), `return_disposal_evidence_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(record?.custodyDigest), `return_disposal_custody_digest_invalid:${ref}`);
  addReason(reasons, product !== undefined && !hlcAfter(record?.recordedAtHlc, product.receivedAtHlc), `return_disposal_time_not_after_receipt:${ref}`);
  addReason(reasons, record?.metadataOnly !== true, `return_disposal_metadata_only_attestation_absent:${ref}`);
  addReason(reasons, record?.protectedContentExcluded !== true, `return_disposal_protected_content_boundary_absent:${ref}`);
}

function evaluateReturnDisposalRecords(input, productsByRef, reasons) {
  const records = Array.isArray(input?.returnDisposalRecords) ? input.returnDisposalRecords : [];
  addReason(reasons, records.length === 0, 'return_disposal_record_list_absent');
  const recordTypes = sortedTextList(records.map((record) => record?.recordType));
  addReason(reasons, !recordTypes.includes('return_to_sponsor'), 'return_record_absent');
  addReason(reasons, !recordTypes.some((type) => type === 'destruction' || type === 'disposal'), 'disposal_record_absent');
  for (const record of records) {
    evaluateReturnDisposalRecord(record, productsByRef, reasons);
  }
  return records;
}

function evaluateAccountabilityControls(input, reasons) {
  const controls = input?.accountabilityControls;
  addReason(reasons, !nonNegativeInteger(controls?.openVarianceCount), 'open_variance_count_invalid');
  addReason(reasons, Number.isSafeInteger(controls?.openVarianceCount) && controls.openVarianceCount > 0, 'open_variance_count_present');
  addReason(reasons, !nonNegativeInteger(controls?.openNonconformityCount), 'open_nonconformity_count_invalid');
  addReason(reasons, Number.isSafeInteger(controls?.openNonconformityCount) && controls.openNonconformityCount > 0, 'open_nonconformity_count_present');
  addReason(reasons, controls?.allDispensingRecordsWitnessed !== true, 'dispensing_witness_control_incomplete');
  addReason(reasons, controls?.allParticipantIdentifiersSuppressed !== true, 'participant_identifier_boundary_incomplete');
  addReason(reasons, !isDigest(controls?.stockReconciliationHash), 'stock_reconciliation_hash_invalid');
  addReason(reasons, !isDigest(controls?.accessReviewHash), 'access_review_hash_invalid');
  addReason(reasons, !isDigest(controls?.blindingReviewHash), 'blinding_review_hash_invalid');
  addReason(reasons, !isDigest(controls?.returnDisposalReconciliationHash), 'return_disposal_reconciliation_hash_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_only_attestation_absent');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_content_boundary_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'reviewer_absent');
  addReason(reasons, !hasText(review?.productManagerDid), 'product_manager_absent');
  addReason(reasons, !hasText(review?.qualityReviewerDid), 'quality_reviewer_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'review_decision_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.accountabilityPlan?.assessedAtHlc), 'review_time_not_after_assessment');
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

function accountabilityId(input) {
  return `cmctpa_${sha256Hex({
    lotRefs: sortedTextList((Array.isArray(input?.productLots) ? input.productLots : []).map((product) => product?.lotRef)),
    planRef: input?.accountabilityPlan?.planRef ?? null,
    productRefs: sortedTextList((Array.isArray(input?.productLots) ? input.productLots : []).map((product) => product?.productRef)),
    protocolRef: input?.accountabilityPlan?.protocolRef ?? null,
    siteRef: input?.accountabilityPlan?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildAccountabilitySummary(input, domainState, uniqueReasons) {
  const productLots = Array.isArray(input?.productLots) ? input.productLots : [];
  const dispensingRecords = Array.isArray(input?.dispensingRecords) ? input.dispensingRecords : [];
  const returnDisposalRecords = Array.isArray(input?.returnDisposalRecords) ? input.returnDisposalRecords : [];

  return {
    schema: 'cybermedica.clinical_trial_product_accountability_summary.v1',
    accountabilityId: accountabilityId(input),
    planRef: input?.accountabilityPlan?.planRef ?? null,
    protocolRef: input?.accountabilityPlan?.protocolRef ?? null,
    siteRef: input?.accountabilityPlan?.siteRef ?? null,
    reconciliationStatus: uniqueReasons.length === 0 ? 'reconciled' : 'blocked',
    productLotCount: productLots.length,
    dispensingRecordCount: dispensingRecords.length,
    returnDisposalRecordCount: returnDisposalRecords.length,
    requiredDomains: domainState.requiredDomains,
    coveredDomains: domainState.coveredDomains,
    openVarianceCount: input?.accountabilityControls?.openVarianceCount ?? null,
    openNonconformityCount: input?.accountabilityControls?.openNonconformityCount ?? null,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createAccountabilityReceipt(input, accountability, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'clinical_trial_product_accountability',
    artifactVersion: accountability.reconciliationStatus,
    classification: 'clinical_trial_product_accountability_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['clinical_trial_product_metadata', 'metadata_only', 'product_accountability'],
    sourceSystem: 'cybermedica.clinical_trial_product_accountability',
    tenantId: input.tenantId,
  });
}

export function evaluateClinicalTrialProductAccountability(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAccountabilityPlan(input, reasons);
  const domainState = evaluateRequiredDomains(input, reasons);
  const productLots = evaluateProductLots(input, reasons);
  const productsByRef = productMap(productLots);
  evaluateDispensingRecords(input, productsByRef, reasons);
  evaluateReturnDisposalRecords(input, productsByRef, reasons);
  evaluateAccountabilityControls(input, reasons);
  evaluateHumanReview(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const accountability = buildAccountabilitySummary(input, domainState, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: PRODUCT_ACCOUNTABILITY_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      accountability,
      receipt: null,
    };
  }

  const artifactHash = sha256Hex({
    accountabilityId: accountability.accountabilityId,
    coveredDomains: accountability.coveredDomains,
    decisionForumReceipt: input.humanReview.decisionForum.workflowReceiptId,
    dispensingRefs: sortedTextList(input.dispensingRecords.map((record) => record.dispensingRef)),
    lotRefs: sortedTextList(input.productLots.map((product) => product.lotRef)),
    planRef: input.accountabilityPlan.planRef,
    protocolRef: input.accountabilityPlan.protocolRef,
    reconciliationStatus: accountability.reconciliationStatus,
    returnDisposalRefs: sortedTextList(input.returnDisposalRecords.map((record) => record.recordRef)),
    tenantId: input.tenantId,
  });
  const receipt = createAccountabilityReceipt(input, accountability, artifactHash);

  return {
    schema: PRODUCT_ACCOUNTABILITY_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    accountability,
    receipt,
  };
}
