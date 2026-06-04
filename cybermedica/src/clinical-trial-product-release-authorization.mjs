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
const REQUIRED_PERMISSION = 'authorize_product_release';
const RELEASE_AUTHORIZATION_SCHEMA = 'cybermedica.clinical_trial_product_release_authorization.v1';

const REQUIRED_RELEASE_DOMAINS = Object.freeze([
  'access_control',
  'accountability_reconciliation',
  'blinding_randomization',
  'dispensing_authorization',
  'enrollment_gate',
  'expiration_control',
  'launch_authorization',
  'protocol_version',
  'storage_temperature',
  'visit_fit',
]);

const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const ACTIVE_RELEASE_STATUSES = new Set(['ready_for_release']);
const REVIEW_DECISIONS = new Set(['product_release_authorized', 'hold_product_release']);

const RAW_RELEASE_FIELDS = new Set([
  'assignmentnarrative',
  'batchserialnumber',
  'directidentifier',
  'dispensingnote',
  'participantidentifier',
  'participantname',
  'patientname',
  'productreleasenarrative',
  'rawdispensingrecord',
  'rawpayload',
  'rawproduct',
  'rawproductrecord',
  'rawproductrelease',
  'rawproductreleasenarrative',
  'rawserialnumber',
  'serialnumber',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
  'unblindedassignment',
]);

const SECRET_RELEASE_FIELDS = new Set([
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

function assertNoReleaseProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoReleaseProtectedContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RELEASE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw clinical trial product release field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RELEASE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`clinical trial product release secret field is not allowed at ${path}.${key}`);
    }
    assertNoReleaseProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoReleaseProtectedContent(input ?? {});
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'manage_product_accountability') &&
      !hasAuthorityPermission(input?.authority, 'govern'),
    'product_release_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateReleasePlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.releaseRef), 'release_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.protocolVersionRef), 'protocol_version_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'study_ref_absent');
  addReason(reasons, !ACTIVE_RELEASE_STATUSES.has(plan?.status), 'release_plan_not_ready');
  addReason(reasons, !isDigest(plan?.releaseSopHash), 'release_sop_hash_invalid');
  addReason(reasons, !isDigest(plan?.protocolVersionHash), 'protocol_version_hash_invalid');
  addReason(reasons, !isDigest(plan?.accountabilitySummaryHash), 'accountability_summary_hash_invalid');
  addReason(reasons, !hasText(plan?.launchAuthorizationRef), 'launch_authorization_ref_absent');
  addReason(reasons, !hasText(plan?.enrollmentGateRef), 'enrollment_gate_ref_absent');
  addReason(reasons, hlcTuple(plan?.assessedAtHlc) === null, 'assessment_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateRequiredDomains(input, reasons) {
  const requiredDomains = sortedTextList(input?.releasePlan?.requiredDomains);
  for (const domainRef of REQUIRED_RELEASE_DOMAINS) {
    addReason(reasons, !requiredDomains.includes(domainRef), `required_domain_missing:${domainRef}`);
  }
  for (const domainRef of requiredDomains) {
    addReason(reasons, !REQUIRED_RELEASE_DOMAINS.includes(domainRef), `required_domain_unsupported:${domainRef}`);
  }

  const coveredDomains = sortedTextList(
    (Array.isArray(input?.releaseControls?.domainEvidence) ? input.releaseControls.domainEvidence : [])
      .filter((entry) => VERIFIED_DOMAIN_STATUSES.has(entry?.status) && isDigest(entry?.evidenceHash))
      .map((entry) => entry.domainRef),
  );
  for (const domainRef of REQUIRED_RELEASE_DOMAINS) {
    addReason(reasons, !coveredDomains.includes(domainRef), `domain_evidence_missing:${domainRef}`);
  }
  return { coveredDomains, requiredDomains };
}

function evaluateProductLot(product, input, reasons) {
  const ref = hasText(product?.productRef) ? product.productRef : 'unknown';
  const availableForRelease =
    nonNegativeInteger(product?.quantityOnHand) && nonNegativeInteger(product?.quantityQuarantined)
      ? product.quantityOnHand - product.quantityQuarantined
      : null;

  addReason(reasons, !hasText(product?.productRef), 'product_ref_absent');
  addReason(reasons, !hasText(product?.lotRef), `product_lot_ref_absent:${ref}`);
  addReason(reasons, product?.protocolRef !== input?.releasePlan?.protocolRef, `product_protocol_mismatch:${ref}`);
  addReason(reasons, product?.currentProtocolVersionRef !== input?.releasePlan?.protocolVersionRef, `product_protocol_version_mismatch:${ref}`);
  addReason(reasons, product?.siteRef !== input?.releasePlan?.siteRef, `product_site_mismatch:${ref}`);
  addReason(reasons, !hasText(product?.sponsorRef), `product_sponsor_absent:${ref}`);
  addReason(reasons, !hasText(product?.accountabilityRef), `product_accountability_ref_absent:${ref}`);
  addReason(reasons, !isDigest(product?.accountabilityRecordHash), `product_accountability_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.batchSerialHash), `product_batch_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.storageControlHash), `product_storage_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.temperatureControlHash), `product_temperature_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.accessControlHash), `product_access_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.blindingControlHash), `product_blinding_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(product?.randomizationPlanHash), `product_randomization_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(product?.receivedAtHlc) === null, `product_receipt_time_invalid:${ref}`);
  addReason(reasons, !hlcAfter(product?.expirationAtHlc, input?.releasePlan?.assessedAtHlc), `product_expired_or_expiration_time_invalid:${ref}`);
  addReason(reasons, !nonNegativeInteger(product?.quantityOnHand), `product_quantity_on_hand_invalid:${ref}`);
  addReason(reasons, !nonNegativeInteger(product?.quantityQuarantined), `product_quantity_quarantined_invalid:${ref}`);
  addReason(reasons, !nonNegativeInteger(product?.quantityRequestedForRelease), `product_release_quantity_invalid:${ref}`);
  addReason(reasons, !nonNegativeInteger(product?.openVarianceCount), `product_open_variance_count_invalid:${ref}`);
  addReason(reasons, Number.isSafeInteger(product?.openVarianceCount) && product.openVarianceCount > 0, `product_open_variance_present:${ref}`);
  addReason(
    reasons,
    availableForRelease !== null &&
      Number.isSafeInteger(product?.quantityRequestedForRelease) &&
      product.quantityRequestedForRelease > availableForRelease,
    `product_release_quantity_exceeds_available:${ref}`,
  );
  addReason(reasons, product?.metadataOnly !== true, `product_metadata_boundary_invalid:${ref}`);
  addReason(reasons, product?.protectedContentExcluded !== true, `product_protected_boundary_invalid:${ref}`);
}

function evaluateProductLots(input, reasons) {
  const products = Array.isArray(input?.productLots) ? input.productLots : [];
  addReason(reasons, products.length === 0, 'product_lot_list_absent');
  for (const product of products) {
    evaluateProductLot(product, input, reasons);
  }
  return products;
}

function evaluateReleaseControls(controls, plan, reasons) {
  addReason(reasons, controls?.launchAuthorized !== true, 'launch_authorization_absent');
  addReason(reasons, controls?.enrollmentGateOpen !== true, 'enrollment_gate_not_open');
  addReason(reasons, controls?.accountabilityReconciled !== true, 'accountability_not_reconciled');
  addReason(reasons, controls?.storageTemperatureAcceptable !== true, 'storage_temperature_not_acceptable');
  addReason(reasons, controls?.accessReviewCurrent !== true, 'access_review_not_current');
  addReason(reasons, controls?.visitWindowVerified !== true, 'visit_window_not_verified');
  addReason(reasons, controls?.participantIdentifiersSuppressed !== true, 'participant_identifier_boundary_incomplete');
  addReason(reasons, !hlcAfter(controls?.releaseWindowClosesAtHlc, plan?.assessedAtHlc), 'release_window_closed_or_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_boundary_invalid');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_boundary_invalid');

  const emergency = controls?.emergencyUnblinding;
  if (emergency?.requested === true) {
    addReason(reasons, emergency?.authorized !== true, 'emergency_unblinding_not_authorized');
    addReason(reasons, !hasText(emergency?.reasonCode), 'emergency_unblinding_reason_absent');
    addReason(reasons, !hasText(emergency?.authorizedByDid), 'emergency_unblinding_authorizer_absent');
    addReason(reasons, !isDigest(emergency?.authorizationHash), 'emergency_unblinding_authorization_hash_invalid');
  }
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'reviewer_absent');
  addReason(reasons, !hasText(review?.productManagerDid), 'product_manager_absent');
  addReason(reasons, !hasText(review?.qualityReviewerDid), 'quality_reviewer_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'review_decision_invalid');
  addReason(reasons, review?.decision !== 'product_release_authorized', 'product_release_not_authorized');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.releasePlan?.assessedAtHlc), 'review_time_not_after_assessment');
  addReason(reasons, !hlcBeforeOrEqual(review?.reviewedAtHlc, input?.releaseControls?.releaseWindowClosesAtHlc), 'review_after_release_window');
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

function releaseAuthorizationId(input) {
  return `cmctp_release_${sha256Hex({
    lotRefs: sortedTextList((Array.isArray(input?.productLots) ? input.productLots : []).map((product) => product?.lotRef)),
    productRefs: sortedTextList((Array.isArray(input?.productLots) ? input.productLots : []).map((product) => product?.productRef)),
    protocolRef: input?.releasePlan?.protocolRef ?? null,
    protocolVersionRef: input?.releasePlan?.protocolVersionRef ?? null,
    releaseRef: input?.releasePlan?.releaseRef ?? null,
    siteRef: input?.releasePlan?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function totalRequestedQuantity(productLots) {
  return productLots.reduce(
    (sum, product) => (Number.isSafeInteger(product?.quantityRequestedForRelease) ? sum + product.quantityRequestedForRelease : sum),
    0,
  );
}

function buildReleaseSummary(input, domainState, productLots, uniqueReasons) {
  return {
    schema: 'cybermedica.clinical_trial_product_release_authorization_summary.v1',
    releaseAuthorizationId: releaseAuthorizationId(input),
    releaseRef: input?.releasePlan?.releaseRef ?? null,
    protocolRef: input?.releasePlan?.protocolRef ?? null,
    protocolVersionRef: input?.releasePlan?.protocolVersionRef ?? null,
    siteRef: input?.releasePlan?.siteRef ?? null,
    authorizationStatus: uniqueReasons.length === 0 ? 'authorized' : 'blocked',
    productLotCount: productLots.length,
    totalRequestedQuantity: totalRequestedQuantity(productLots),
    requiredDomains: domainState.requiredDomains,
    coveredDomains: domainState.coveredDomains,
    launchAuthorized: input?.releaseControls?.launchAuthorized === true,
    enrollmentGateOpen: input?.releaseControls?.enrollmentGateOpen === true,
    emergencyUnblindingRequested: input?.releaseControls?.emergencyUnblinding?.requested === true,
    aiFinalAuthority: input?.actor?.kind === 'ai_agent' || input?.humanReview?.aiFinalAuthority === true,
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createReleaseReceipt(input, release, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'clinical_trial_product_release_authorization',
    artifactVersion: release.authorizationStatus,
    classification: 'clinical_trial_product_release_authorization_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['clinical_trial_product_metadata', 'metadata_only', 'product_release_authorization'],
    sourceSystem: 'cybermedica.clinical_trial_product_release_authorization',
    tenantId: input.tenantId,
  });
}

export function evaluateClinicalTrialProductReleaseAuthorization(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReleasePlan(input?.releasePlan, reasons);
  const domainState = evaluateRequiredDomains(input, reasons);
  const productLots = evaluateProductLots(input, reasons);
  evaluateReleaseControls(input?.releaseControls, input?.releasePlan, reasons);
  evaluateHumanReview(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const release = buildReleaseSummary(input, domainState, productLots, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: RELEASE_AUTHORIZATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      release,
      receipt: null,
    };
  }

  const artifactHash = sha256Hex({
    authorizationStatus: release.authorizationStatus,
    coveredDomains: release.coveredDomains,
    decisionForumReceipt: input.humanReview.decisionForum.workflowReceiptId,
    lotRefs: sortedTextList(input.productLots.map((product) => product.lotRef)),
    productRefs: sortedTextList(input.productLots.map((product) => product.productRef)),
    protocolRef: input.releasePlan.protocolRef,
    protocolVersionRef: input.releasePlan.protocolVersionRef,
    releaseAuthorizationId: release.releaseAuthorizationId,
    releaseRef: input.releasePlan.releaseRef,
    tenantId: input.tenantId,
    totalRequestedQuantity: release.totalRequestedQuantity,
  });
  const receipt = createReleaseReceipt(input, release, artifactHash);

  return {
    schema: RELEASE_AUTHORIZATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    release,
    receipt,
  };
}
