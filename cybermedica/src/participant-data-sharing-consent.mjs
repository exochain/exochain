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
const REQUIRED_PERMISSIONS = new Set(['govern', 'manage_participant_data_sharing', 'obtain_consent']);
const ALLOWED_ACTOR_KINDS = new Set(['human']);
const ACTIVE_STATUSES = new Set(['active']);
const GRANTED_STATUSES = new Set(['granted']);
const SUPPRESSION_MODES = new Set(['metadata_only_pseudonymous']);

const RAW_DATA_SHARING_FIELDS = new Set([
  'directidentifier',
  'directidentifierlist',
  'participantlisting',
  'participantname',
  'rawconsent',
  'rawdataset',
  'rawdatasharingconsent',
  'rawdisclosure',
  'rawpayload',
  'rawrequest',
  'rawsourcedata',
  'sourcedocumentbody',
]);

const SECRET_DATA_SHARING_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'secret',
  'sessionsecret',
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

function assertNoRawDataSharingContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDataSharingContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DATA_SHARING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protected content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DATA_SHARING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`data sharing secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDataSharingContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDataSharingContent(input ?? {});
  canonicalize(input ?? {});
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

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAnyPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.some((permission) => REQUIRED_PERMISSIONS.has(permission));
}

function listMissingFromSubset(values, allowed, prefix, reasons) {
  const allowedSet = new Set(allowed);
  for (const value of values) {
    addReason(reasons, !allowedSet.has(value), `${prefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ALLOWED_ACTOR_KINDS.has(input?.actor?.kind), 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAnyPermission(input?.authority), 'data_sharing_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateParticipant(input, reasons) {
  const participant = input?.participant;
  const consent = input?.dataSharingConsent;
  addReason(reasons, !isDigest(participant?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(participant?.consentProcessRecordId), 'consent_process_record_absent');
  addReason(reasons, !hasText(participant?.consentMaterialReceiptId), 'consent_material_receipt_absent');
  addReason(reasons, !hasText(participant?.consentBailmentRef), 'participant_consent_bailment_absent');
  addReason(
    reasons,
    hasText(participant?.consentBailmentRef) &&
      hasText(consent?.consentBailmentRef) &&
      participant.consentBailmentRef !== consent.consentBailmentRef,
    'consent_bailment_mismatch',
  );
}

function evaluateSharingRequest(input, reasons) {
  const request = input?.sharingRequest;
  const review = input?.humanReview;
  const requestExpiry = hlcTuple(request?.expiresAtHlc);
  const reviewTime = hlcTuple(review?.reviewedAtHlc);

  addReason(reasons, !hasText(request?.requestRef), 'sharing_request_ref_absent');
  addReason(reasons, !hasText(request?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(request?.interestedPartyClass), 'interested_party_class_absent');
  addReason(reasons, !hasText(request?.recipientTenantId), 'recipient_tenant_absent');
  addReason(reasons, !hasText(request?.purpose), 'sharing_purpose_absent');
  addReason(reasons, sortedTextList(request?.requestedScopeRefs).length === 0, 'requested_scope_refs_absent');
  addReason(reasons, sortedTextList(request?.requestedDataClassRefs).length === 0, 'requested_data_class_refs_absent');
  addReason(reasons, request?.metadataOnly !== true, 'sharing_request_metadata_boundary_invalid');
  addReason(reasons, request?.productionTrustClaim === true, 'sharing_request_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'sharing_requested_time_invalid');
  addReason(reasons, hlcTuple(request?.expiresAtHlc) === null, 'sharing_request_expiry_invalid');
  addReason(reasons, !hlcAfter(request?.expiresAtHlc, request?.requestedAtHlc), 'sharing_request_expiry_not_after_request');
  addReason(
    reasons,
    requestExpiry !== null && reviewTime !== null && compareHlc(requestExpiry, reviewTime) <= 0,
    'sharing_request_expired_before_review',
  );
}

function evaluatePolicy(input, reasons) {
  const policy = input?.sharingPolicy;
  const request = input?.sharingRequest;
  const allowedParties = sortedTextList(policy?.allowedInterestedPartyClasses);
  const allowedPurposes = sortedTextList(policy?.allowedPurposes);
  const allowedScopes = sortedTextList(policy?.allowedScopeRefs);
  const allowedDataClasses = sortedTextList(policy?.allowedDataClassRefs);
  const requestedScopes = sortedTextList(request?.requestedScopeRefs);
  const requestedDataClasses = sortedTextList(request?.requestedDataClassRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'sharing_policy_ref_absent');
  addReason(reasons, !ACTIVE_STATUSES.has(policy?.status), 'sharing_policy_not_active');
  addReason(reasons, !isDigest(policy?.policyHash), 'sharing_policy_hash_invalid');
  addReason(reasons, allowedParties.length === 0, 'sharing_policy_interested_party_classes_absent');
  addReason(reasons, allowedPurposes.length === 0, 'sharing_policy_purposes_absent');
  addReason(reasons, allowedScopes.length === 0, 'sharing_policy_scopes_absent');
  addReason(reasons, allowedDataClasses.length === 0, 'sharing_policy_data_classes_absent');
  addReason(reasons, hasText(request?.interestedPartyClass) && !allowedParties.includes(request.interestedPartyClass), 'interested_party_class_not_allowed');
  addReason(reasons, hasText(request?.purpose) && !allowedPurposes.includes(request.purpose), 'sharing_purpose_not_allowed');
  listMissingFromSubset(requestedScopes, allowedScopes, 'requested_scope_not_allowed', reasons);
  listMissingFromSubset(requestedDataClasses, allowedDataClasses, 'requested_data_class_not_allowed', reasons);
  addReason(reasons, policy?.metadataOnly !== true, 'sharing_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.directIdentifiersAllowed === true, 'direct_identifier_boundary_invalid');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'disclosure_log_not_required_by_policy');
  addReason(reasons, !isDigest(policy?.retentionPolicyHash), 'retention_policy_hash_invalid');
  addReason(reasons, !isDigest(policy?.privacyComplianceHash), 'privacy_compliance_hash_invalid');
  addReason(reasons, hlcTuple(policy?.effectiveAtHlc) === null, 'sharing_policy_effective_time_invalid');
}

function evaluateDataSharingConsent(input, reasons) {
  const consent = input?.dataSharingConsent;
  const request = input?.sharingRequest;
  const policy = input?.sharingPolicy;
  const review = input?.humanReview;
  const grantedScopes = sortedTextList(consent?.grantedScopeRefs);
  const grantedDataClasses = sortedTextList(consent?.grantedDataClassRefs);
  const interestedParties = sortedTextList(consent?.interestedPartyClassRefs);
  const requestedScopes = sortedTextList(request?.requestedScopeRefs);
  const requestedDataClasses = sortedTextList(request?.requestedDataClassRefs);
  const consentExpiry = hlcTuple(consent?.expiresAtHlc);
  const reviewTime = hlcTuple(review?.reviewedAtHlc);

  addReason(reasons, !GRANTED_STATUSES.has(consent?.status), 'data_sharing_consent_not_granted');
  addReason(reasons, !isDigest(consent?.evidenceHash), 'data_sharing_consent_evidence_invalid');
  addReason(reasons, !hasText(consent?.consentVersionRef), 'data_sharing_consent_version_absent');
  addReason(reasons, hlcTuple(consent?.documentedAtHlc) === null, 'data_sharing_consent_documented_time_invalid');
  addReason(reasons, hlcTuple(consent?.expiresAtHlc) === null, 'data_sharing_consent_expiry_invalid');
  addReason(reasons, !hlcAfter(consent?.expiresAtHlc, request?.requestedAtHlc), 'data_sharing_consent_expired');
  addReason(
    reasons,
    consentExpiry !== null && reviewTime !== null && compareHlc(consentExpiry, reviewTime) <= 0,
    'data_sharing_consent_expired_before_review',
  );
  addReason(reasons, grantedScopes.length === 0, 'data_sharing_granted_scopes_absent');
  addReason(reasons, grantedDataClasses.length === 0, 'data_sharing_granted_data_classes_absent');
  addReason(reasons, interestedParties.length === 0, 'data_sharing_interested_party_classes_absent');
  listMissingFromSubset(requestedScopes, grantedScopes, 'requested_scope_not_granted', reasons);
  listMissingFromSubset(requestedDataClasses, grantedDataClasses, 'requested_data_class_not_granted', reasons);
  addReason(
    reasons,
    hasText(request?.interestedPartyClass) && !interestedParties.includes(request.interestedPartyClass),
    'interested_party_class_not_granted',
  );
  addReason(reasons, !isDigest(consent?.privacyNoticeHash), 'privacy_notice_hash_invalid');
  addReason(reasons, !isDigest(consent?.retentionPolicyHash), 'consent_retention_policy_hash_invalid');
  addReason(reasons, !isDigest(consent?.withdrawalPathHash), 'withdrawal_path_hash_invalid');
  addReason(reasons, consent?.copyDelivered !== true, 'data_sharing_consent_copy_not_delivered');
  addReason(reasons, !hasText(consent?.consentBailmentRef), 'data_sharing_consent_bailment_absent');
  addReason(
    reasons,
    isDigest(consent?.retentionPolicyHash) && isDigest(policy?.retentionPolicyHash) && consent.retentionPolicyHash !== policy.retentionPolicyHash,
    'retention_policy_mismatch',
  );
  addReason(
    reasons,
    hlcBefore(consent?.documentedAtHlc, policy?.effectiveAtHlc),
    'consent_documented_before_policy_effective',
  );
}

function evaluateDisclosurePlan(input, reasons) {
  const plan = input?.disclosurePlan;
  const consent = input?.dataSharingConsent;
  addReason(reasons, !isDigest(plan?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !SUPPRESSION_MODES.has(plan?.suppressionMode), 'suppression_mode_invalid');
  addReason(reasons, plan?.directIdentifiersExcluded !== true, 'direct_identifier_boundary_invalid');
  addReason(reasons, plan?.rawContentExcluded !== true, 'raw_content_boundary_invalid');
  addReason(reasons, plan?.participantListExcluded !== true, 'participant_list_boundary_invalid');
  addReason(reasons, plan?.sponsorConfidentialContentExcluded !== true, 'sponsor_confidential_boundary_invalid');
  addReason(reasons, plan?.privilegedContentExcluded !== true, 'privileged_content_boundary_invalid');
  addReason(reasons, hlcTuple(plan?.plannedAtHlc) === null, 'disclosure_plan_time_invalid');
  addReason(reasons, hlcBefore(plan?.plannedAtHlc, consent?.documentedAtHlc), 'disclosure_plan_before_consent_documented');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  const plan = input?.disclosurePlan;
  addReason(reasons, review?.approved !== true, 'human_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !isDigest(review?.privacyLegalReviewHash), 'privacy_legal_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, plan?.plannedAtHlc), 'human_review_before_disclosure_plan');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function consentRecordId(input) {
  return `cmdsc_${sha256Hex({
    consentVersionRef: input?.dataSharingConsent?.consentVersionRef ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    recipientTenantId: input?.sharingRequest?.recipientTenantId ?? null,
    requestRef: input?.sharingRequest?.requestRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildDataSharingConsentRecord(input, status, receiptId = null) {
  return {
    schema: 'cybermedica.participant_data_sharing_consent_record.v1',
    consentId: consentRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    consentProcessRecordId: input?.participant?.consentProcessRecordId ?? null,
    consentMaterialReceiptId: input?.participant?.consentMaterialReceiptId ?? null,
    consentBailmentRef: input?.dataSharingConsent?.consentBailmentRef ?? input?.participant?.consentBailmentRef ?? null,
    requestRef: input?.sharingRequest?.requestRef ?? null,
    protocolRef: input?.sharingRequest?.protocolRef ?? null,
    interestedPartyClass: input?.sharingRequest?.interestedPartyClass ?? null,
    recipientTenantId: input?.sharingRequest?.recipientTenantId ?? null,
    purpose: input?.sharingRequest?.purpose ?? null,
    status,
    sharingGate: status === 'active' ? 'passed' : 'blocked',
    consentVersionRef: input?.dataSharingConsent?.consentVersionRef ?? null,
    evidenceHash: input?.dataSharingConsent?.evidenceHash ?? null,
    requestedScopeRefs: sortedTextList(input?.sharingRequest?.requestedScopeRefs),
    requestedDataClassRefs: sortedTextList(input?.sharingRequest?.requestedDataClassRefs),
    grantedScopeRefs: sortedTextList(input?.dataSharingConsent?.grantedScopeRefs),
    grantedDataClassRefs: sortedTextList(input?.dataSharingConsent?.grantedDataClassRefs),
    interestedPartyClassRefs: sortedTextList(input?.dataSharingConsent?.interestedPartyClassRefs),
    policyRef: input?.sharingPolicy?.policyRef ?? null,
    policyHash: input?.sharingPolicy?.policyHash ?? null,
    privacyNoticeHash: input?.dataSharingConsent?.privacyNoticeHash ?? null,
    privacyComplianceHash: input?.sharingPolicy?.privacyComplianceHash ?? null,
    retentionPolicyHash: input?.dataSharingConsent?.retentionPolicyHash ?? null,
    withdrawalPathHash: input?.dataSharingConsent?.withdrawalPathHash ?? null,
    disclosureLogHash: input?.disclosurePlan?.disclosureLogHash ?? null,
    directIdentifiersExcluded: input?.disclosurePlan?.directIdentifiersExcluded === true,
    rawContentExcluded: input?.disclosurePlan?.rawContentExcluded === true,
    documentedAtHlc: input?.dataSharingConsent?.documentedAtHlc ?? null,
    expiresAtHlc: input?.dataSharingConsent?.expiresAtHlc ?? null,
    reviewedAtHlc: input?.humanReview?.reviewedAtHlc ?? null,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createDataSharingConsentReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_data_sharing_consent',
    artifactVersion: `${record.consentId}@${record.consentVersionRef}`,
    classification: 'participant_data_sharing_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['participant_data_sharing', 'metadata_only', 'revocation_capable'],
    sourceSystem: 'cybermedica.participant_data_sharing_consent',
    tenantId: input.tenantId,
  });
}

export function evaluateParticipantDataSharingConsent(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateParticipant(input, reasons);
  evaluateSharingRequest(input, reasons);
  evaluatePolicy(input, reasons);
  evaluateDataSharingConsent(input, reasons);
  evaluateDisclosurePlan(input, reasons);
  evaluateHumanReview(input, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: 'cybermedica.participant_data_sharing_consent_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      dataSharingConsentRecord: buildDataSharingConsentRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildDataSharingConsentRecord(input, 'active');
  const artifactHash = sha256Hex({
    consentBailmentRef: record.consentBailmentRef,
    consentId: record.consentId,
    consentMaterialReceiptId: record.consentMaterialReceiptId,
    consentProcessRecordId: record.consentProcessRecordId,
    consentVersionRef: record.consentVersionRef,
    disclosureLogHash: record.disclosureLogHash,
    evidenceHash: record.evidenceHash,
    expiresAtHlc: record.expiresAtHlc,
    grantedDataClassRefs: record.grantedDataClassRefs,
    grantedScopeRefs: record.grantedScopeRefs,
    interestedPartyClass: record.interestedPartyClass,
    participantCodeHash: record.participantCodeHash,
    policyHash: record.policyHash,
    privacyComplianceHash: record.privacyComplianceHash,
    privacyNoticeHash: record.privacyNoticeHash,
    purpose: record.purpose,
    recipientTenantId: record.recipientTenantId,
    requestedDataClassRefs: record.requestedDataClassRefs,
    requestedScopeRefs: record.requestedScopeRefs,
    tenantId: record.tenantId,
    withdrawalPathHash: record.withdrawalPathHash,
  });
  const receipt = createDataSharingConsentReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_data_sharing_consent_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    dataSharingConsentRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
