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
const PARTICIPANT_RIGHTS_SCHEMA = 'cybermedica.participant_rights_request.v1';

const REQUIRED_PERMISSIONS = new Set(['govern', 'manage_participant_rights', 'privacy_review', 'write']);
const ACTOR_KINDS = new Set(['human']);
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const PARTICIPANT_STATUSES = new Set(['active', 'enrolled', 'follow_up', 'screened', 'withdrawn', 'lost_to_follow_up']);
const REQUESTER_CLASSES = new Set([
  'data_custodian',
  'legally_authorized_representative',
  'participant',
  'privacy_officer',
  'site_staff',
]);
const REQUEST_TYPES = new Set([
  'access_review',
  'accounting_of_disclosures',
  'amendment_review',
  'data_sharing_preference_review',
  'restriction_review',
  'retention_disposition_review',
]);
const HUMAN_REVIEW_DECISIONS = new Set([
  'denied_by_policy',
  'fulfilled_metadata_only',
  'held_for_privacy_governance',
]);

const RAW_PARTICIPANT_RIGHTS_FIELDS = new Set([
  'body',
  'content',
  'directidentifier',
  'directidentifierlist',
  'fullrecordbody',
  'medicalrecordbody',
  'participantidentifier',
  'participantlisting',
  'participantname',
  'privacyrequestbody',
  'rawaccessrequest',
  'rawamendmentrequest',
  'rawparticipantrequest',
  'rawprivacyrequest',
  'rawrecord',
  'rawrequest',
  'rawresponse',
  'rawsourcedata',
  'recordbody',
  'responsebody',
  'sourcedocumentbody',
]);

const SECRET_PARTICIPANT_RIGHTS_FIELDS = new Set([
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

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
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

function assertNoRawParticipantRightsContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawParticipantRightsContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PARTICIPANT_RIGHTS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`participant rights protected content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PARTICIPANT_RIGHTS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`participant rights secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawParticipantRightsContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawParticipantRightsContent(input ?? {});
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

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hasAnyRequiredPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.some((permission) => REQUIRED_PERMISSIONS.has(permission));
}

function listUnsupported(values, allowed, prefix, reasons) {
  for (const value of values) {
    addReason(reasons, !allowed.has(value), `${prefix}:${value}`);
  }
}

function listMissingSubset(values, allowedValues, prefix, reasons) {
  const allowed = new Set(allowedValues);
  for (const value of values) {
    addReason(reasons, !allowed.has(value), `${prefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAnyRequiredPermission(input?.authority), 'participant_rights_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateParticipant(input, reasons) {
  const participant = input?.participant;
  addReason(reasons, !hasText(participant?.participantCodeRecordId), 'participant_code_record_id_absent');
  addReason(reasons, !isDigest(participant?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(participant?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(participant?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(participant?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(participant?.consentBailmentRef), 'consent_bailment_ref_absent');
  addReason(reasons, !PARTICIPANT_STATUSES.has(participant?.currentStatus), 'participant_status_invalid');
}

function evaluateRightsPolicy(input, reasons) {
  const policy = input?.rightsPolicy;
  const request = input?.request;
  const allowedRequestTypes = sortedTextList(policy?.allowedRequestTypes);
  const allowedScopeRefs = sortedTextList(policy?.allowedScopeRefs);
  const allowedDataClassRefs = sortedTextList(policy?.allowedDataClassRefs);
  const requestedScopeRefs = sortedTextList(request?.requestedScopeRefs);
  const requestedDataClassRefs = sortedTextList(request?.requestedDataClassRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'rights_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'rights_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'rights_policy_not_active');
  addReason(reasons, allowedRequestTypes.length === 0, 'rights_policy_request_types_absent');
  addReason(reasons, allowedScopeRefs.length === 0, 'rights_policy_scope_refs_absent');
  addReason(reasons, allowedDataClassRefs.length === 0, 'rights_policy_data_class_refs_absent');
  listUnsupported(allowedRequestTypes, REQUEST_TYPES, 'rights_policy_request_type_unsupported', reasons);
  listMissingSubset(requestedScopeRefs, allowedScopeRefs, 'rights_request_scope_not_allowed', reasons);
  listMissingSubset(requestedDataClassRefs, allowedDataClassRefs, 'rights_request_data_class_not_allowed', reasons);
  addReason(reasons, policy?.metadataOnly !== true, 'rights_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.directIdentifierResponseForbidden !== true, 'direct_identifier_response_policy_missing');
  addReason(reasons, policy?.retentionOverrideForbidden !== true, 'retention_override_policy_missing');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'disclosure_log_policy_missing');
  addReason(reasons, hlcTuple(policy?.effectiveAtHlc) === null, 'rights_policy_effective_time_invalid');
  addReason(
    reasons,
    hlcTuple(policy?.effectiveAtHlc) !== null &&
      hlcTuple(request?.requestedAtHlc) !== null &&
      hlcBefore(request.requestedAtHlc, policy.effectiveAtHlc),
    'rights_request_before_policy_effective',
  );
}

function evaluateRightsRequest(input, reasons) {
  const request = input?.request;
  const allowedRequestTypes = sortedTextList(input?.rightsPolicy?.allowedRequestTypes);
  const requestedScopeRefs = sortedTextList(request?.requestedScopeRefs);
  const requestedDataClassRefs = sortedTextList(request?.requestedDataClassRefs);

  addReason(reasons, !hasText(request?.requestRef), 'rights_request_ref_absent');
  addReason(reasons, !REQUEST_TYPES.has(request?.requestType), 'rights_request_type_unsupported');
  addReason(
    reasons,
    REQUEST_TYPES.has(request?.requestType) && !allowedRequestTypes.includes(request.requestType),
    'rights_request_type_not_allowed',
  );
  addReason(reasons, !REQUESTER_CLASSES.has(request?.requesterClass), 'rights_requester_class_invalid');
  addReason(reasons, requestedScopeRefs.length === 0, 'rights_request_scope_refs_absent');
  addReason(reasons, requestedDataClassRefs.length === 0, 'rights_request_data_class_refs_absent');
  addReason(reasons, request?.metadataOnly !== true, 'rights_request_metadata_boundary_invalid');
  addReason(reasons, request?.productionTrustClaim === true, 'rights_request_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'rights_request_time_invalid');
}

function evaluateIdentityVerification(input, reasons) {
  const verification = input?.identityVerification;
  const request = input?.request;

  addReason(reasons, verification?.verified !== true, 'identity_verification_absent');
  addReason(
    reasons,
    hasText(verification?.requesterClass) &&
      hasText(request?.requesterClass) &&
      verification.requesterClass !== request.requesterClass,
    'identity_verification_requester_mismatch',
  );
  addReason(reasons, !isDigest(verification?.verificationEvidenceHash), 'identity_verification_evidence_invalid');
  addReason(
    reasons,
    request?.requesterClass === 'legally_authorized_representative' && !isDigest(verification?.authorizationEvidenceHash),
    'representative_authorization_evidence_invalid',
  );
  addReason(reasons, hlcTuple(verification?.verifiedAtHlc) === null, 'identity_verification_time_invalid');
  addReason(
    reasons,
    hlcTuple(verification?.verifiedAtHlc) !== null &&
      hlcTuple(request?.requestedAtHlc) !== null &&
      hlcBefore(verification.verifiedAtHlc, request.requestedAtHlc),
    'identity_verification_before_request',
  );
}

function evaluatePrivacyControls(input, reasons) {
  const controls = input?.privacyControls;
  addReason(reasons, !isDigest(controls?.protectedDataClassificationHash), 'protected_data_classification_hash_invalid');
  addReason(reasons, !isDigest(controls?.accessRestrictionHash), 'access_restriction_hash_invalid');
  addReason(reasons, !isDigest(controls?.retentionPolicyHash), 'retention_policy_hash_invalid');
  addReason(reasons, !hasText(controls?.disclosureLogRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(controls?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(controls?.dataMinimizationHash), 'data_minimization_hash_invalid');
  addReason(reasons, controls?.responsePackageMetadataOnly !== true, 'response_package_metadata_boundary_invalid');
  addReason(reasons, controls?.directIdentifiersExcluded !== true, 'direct_identifier_response_boundary_invalid');
  addReason(reasons, controls?.rawRecordAccessExcluded !== true, 'raw_record_access_boundary_invalid');
  addReason(reasons, controls?.retentionPreserved !== true, 'retention_preservation_absent');
  addReason(reasons, !hasText(controls?.consentTrackingRef), 'consent_tracking_ref_absent');
  addReason(reasons, !isDigest(controls?.consentTrackingHash), 'consent_tracking_hash_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  const request = input?.request;
  const verification = input?.identityVerification;

  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.responsePackageHash), 'response_package_hash_invalid');
  addReason(reasons, !isDigest(review?.participantNotificationHash), 'participant_notification_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(
    reasons,
    hlcTuple(review?.reviewedAtHlc) !== null &&
      ((hlcTuple(verification?.verifiedAtHlc) !== null && hlcNotAfter(review.reviewedAtHlc, verification.verifiedAtHlc)) ||
        (hlcTuple(request?.requestedAtHlc) !== null && hlcNotAfter(review.reviewedAtHlc, request.requestedAtHlc))),
    'human_review_not_after_identity_verification',
  );
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function rightsRequestRecordId(input) {
  const request = input?.request;
  return `cmrights_${sha256Hex({
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    requestRef: request?.requestRef ?? null,
    requestType: request?.requestType ?? null,
    requestedAtHlc: request?.requestedAtHlc ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildRightsRequestRecord(input, status, receiptId = null) {
  const request = input?.request;
  const participant = input?.participant;
  const controls = input?.privacyControls;

  return {
    schema: PARTICIPANT_RIGHTS_SCHEMA,
    rightsRequestRecordId: rightsRequestRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeRecordId: participant?.participantCodeRecordId ?? null,
    participantCodeHash: participant?.participantCodeHash ?? null,
    studyRef: participant?.studyRef ?? null,
    protocolRef: participant?.protocolRef ?? null,
    siteRef: participant?.siteRef ?? null,
    consentBailmentRef: participant?.consentBailmentRef ?? null,
    participantStatus: participant?.currentStatus ?? null,
    policyRef: input?.rightsPolicy?.policyRef ?? null,
    policyHash: input?.rightsPolicy?.policyHash ?? null,
    allowedScopeRefs: sortedTextList(input?.rightsPolicy?.allowedScopeRefs),
    allowedDataClassRefs: sortedTextList(input?.rightsPolicy?.allowedDataClassRefs),
    requestRef: request?.requestRef ?? null,
    requestType: request?.requestType ?? null,
    requesterClass: request?.requesterClass ?? null,
    status,
    requestedScopeRefs: sortedTextList(request?.requestedScopeRefs),
    requestedDataClassRefs: sortedTextList(request?.requestedDataClassRefs),
    requestedAtHlc: request?.requestedAtHlc ?? null,
    identityVerifiedAtHlc: input?.identityVerification?.verifiedAtHlc ?? null,
    reviewedAtHlc: input?.humanReview?.reviewedAtHlc ?? null,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    responsePackageHash: input?.humanReview?.responsePackageHash ?? null,
    participantNotificationHash: input?.humanReview?.participantNotificationHash ?? null,
    disclosureLogRef: controls?.disclosureLogRef ?? null,
    directIdentifiersExcluded: controls?.directIdentifiersExcluded === true,
    rawRecordAccessExcluded: controls?.rawRecordAccessExcluded === true,
    retentionPreserved: controls?.retentionPreserved === true,
    responsePackageMetadataOnly: controls?.responsePackageMetadataOnly === true,
    consentTrackingRef: controls?.consentTrackingRef ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createParticipantRightsReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_rights_request',
    artifactVersion: `${record.requestRef}@${record.requestType}`,
    classification: 'participant_rights_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['metadata_only', 'participant_rights', 'privacy_request'],
    sourceSystem: 'cybermedica.participant_rights_requests',
    tenantId: input.tenantId,
  });
}

export function evaluateParticipantRightsRequest(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateParticipant(input, reasons);
  evaluateRightsPolicy(input, reasons);
  evaluateRightsRequest(input, reasons);
  evaluateIdentityVerification(input, reasons);
  evaluatePrivacyControls(input, reasons);
  evaluateHumanReview(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.participant_rights_request_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      rightsRequestRecord: buildRightsRequestRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildRightsRequestRecord(input, input.humanReview.decision);
  const artifactHash = sha256Hex({
    allowedDataClassRefs: record.allowedDataClassRefs,
    allowedScopeRefs: record.allowedScopeRefs,
    consentBailmentRef: record.consentBailmentRef,
    disclosureLogHash: input.privacyControls.disclosureLogHash,
    participantCodeHash: record.participantCodeHash,
    participantNotificationHash: record.participantNotificationHash,
    requestedDataClassRefs: record.requestedDataClassRefs,
    requestedScopeRefs: record.requestedScopeRefs,
    requestRef: record.requestRef,
    requestType: record.requestType,
    responsePackageHash: record.responsePackageHash,
    rightsRequestRecordId: record.rightsRequestRecordId,
    tenantId: record.tenantId,
  });
  const receipt = createParticipantRightsReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_rights_request_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    rightsRequestRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
