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
const EXPORT_CONTROL_SCHEMA = 'cybermedica.export_control.v1';
const REQUIRED_PERMISSION = 'export_control';
const ACTOR_KINDS = new Set(['human', 'service_account']);
const POLICY_STATUSES = new Set(['active']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);
const SPONSOR_CRO_REQUESTER_CLASSES = new Set(['cro', 'sponsor']);
const SPONSOR_CRO_WORK_ITEM_STATUSES = new Set([
  'queued_for_site_review',
  'routed_to_decision_forum',
  'approved_for_response',
]);
const REQUIRED_CONTROL_DOMAINS = new Set(['access', 'confidentiality', 'disclosure', 'privacy']);
const SUPPRESSION_MODES = new Set(['suppress_without_identifiers']);
const CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'confidential_metadata_only',
  'qms_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);

const RAW_EXPORT_FIELDS = new Set([
  'body',
  'content',
  'directidentifierlist',
  'exportbody',
  'exportpayload',
  'freetext',
  'freetextnote',
  'participantlisting',
  'rawauditrecord',
  'rawdataset',
  'rawdiligencepacket',
  'rawexport',
  'rawexportpayload',
  'rawrecord',
  'rawrequest',
  'rawrequestbody',
  'rawrequestcontent',
  'rawrequestnarrative',
  'rawresponsepackage',
  'rawsource',
  'rawsourcedata',
  'rawsponsorrequest',
  'rawsponsorrequestbody',
  'recordbody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_EXPORT_FIELDS = new Set([
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

function assertNoRawExportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawExportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw export content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`export secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawExportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawExportContent(input ?? {});
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

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) <= 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function includesAll(needles, haystack) {
  const haystackSet = new Set(haystack);
  return needles.every((needle) => haystackSet.has(needle));
}

function textListsIntersect(left, right) {
  const rightSet = new Set(right);
  return left.some((item) => rightSet.has(item));
}

function sameTextSet(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((item, index) => item === right[index]);
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
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'export_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'data_export'),
    'export_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateExportRequest(input, reasons) {
  const request = input?.exportRequest;
  addReason(reasons, !hasText(request?.exportRef), 'export_ref_absent');
  addReason(reasons, !hasText(request?.exportType), 'export_type_absent');
  addReason(reasons, !hasText(request?.purpose), 'export_purpose_absent');
  addReason(reasons, !hasText(request?.recipientTenantId), 'export_recipient_tenant_absent');
  addReason(reasons, !hasText(request?.recipientClass), 'export_recipient_class_absent');
  addReason(reasons, request?.metadataOnly !== true, 'export_metadata_boundary_invalid');
  addReason(reasons, request?.productionTrustClaim === true, 'export_request_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'export_requested_time_invalid');
  addReason(reasons, hlcTuple(request?.generatedAtHlc) === null, 'export_generated_time_invalid');
  addReason(reasons, hlcBefore(request?.generatedAtHlc, request?.requestedAtHlc), 'export_generated_before_request');
}

function evaluateExportControlPolicy(input, reasons) {
  const policy = input?.exportControlPolicy;
  const request = input?.exportRequest;
  const controlDomains = sortedTextList(policy?.requiredControlDomains);
  const allowedExportTypes = sortedTextList(policy?.allowedExportTypes);
  const allowedPurposes = sortedTextList(policy?.allowedPurposes);
  const allowedRecipientClasses = sortedTextList(policy?.allowedRecipientClasses);
  const allowedRoleRefs = sortedTextList(policy?.allowedRoleRefs);
  const allowedSensitivityTags = sortedTextList(policy?.allowedSensitivityTags);
  const allowedPrivacyCategories = sortedTextList(policy?.allowedPrivacyCategories);
  const allowedConfidentialityCategories = sortedTextList(policy?.allowedConfidentialityCategories);

  addReason(reasons, !hasText(policy?.policyRef), 'export_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'export_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'export_policy_not_active');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'export_policy_time_invalid');
  addReason(reasons, hlcTuple(policy?.validUntilHlc) === null, 'export_policy_expiry_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'export_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.sourcePayloadAccessible !== false, 'source_payload_access_forbidden');
  addReason(reasons, policy?.directIdentifiersAllowed !== false, 'direct_identifier_export_forbidden');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'disclosure_log_required_absent');
  addReason(reasons, !SUPPRESSION_MODES.has(policy?.suppressionMode), 'suppression_mode_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'export_policy_production_trust_claim_forbidden');
  addReason(reasons, hlcBefore(policy?.evaluatedAtHlc, request?.requestedAtHlc), 'export_policy_before_request');
  addReason(reasons, hlcNotAfter(policy?.validUntilHlc, request?.generatedAtHlc), 'export_policy_expired');
  addReason(reasons, !allowedExportTypes.includes(request?.exportType), 'export_type_not_allowed');
  addReason(reasons, !allowedPurposes.includes(request?.purpose), 'export_purpose_not_allowed');
  addReason(reasons, !allowedRecipientClasses.includes(request?.recipientClass), 'recipient_class_not_allowed');
  addReason(reasons, allowedRoleRefs.length === 0, 'export_policy_roles_absent');
  addReason(reasons, allowedSensitivityTags.length === 0, 'export_policy_sensitivity_tags_absent');
  addReason(reasons, allowedPrivacyCategories.length === 0, 'export_policy_privacy_categories_absent');
  addReason(reasons, allowedConfidentialityCategories.length === 0, 'export_policy_confidentiality_categories_absent');

  for (const domain of [...REQUIRED_CONTROL_DOMAINS].sort()) {
    addReason(reasons, !controlDomains.includes(domain), `control_domain_missing:${domain}`);
  }
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  const request = input?.exportRequest;
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, log?.purpose !== request?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, log?.recipientClass !== request?.recipientClass, 'disclosure_log_recipient_mismatch');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, log?.includesSuppressedRecordRefs !== false, 'disclosure_log_suppressed_refs_forbidden');
  addReason(reasons, log?.includesDirectIdentifiers !== false, 'disclosure_log_identifiers_forbidden');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.exportControlPolicy?.evaluatedAtHlc), 'disclosure_log_before_policy');
  addReason(reasons, hlcBefore(request?.generatedAtHlc, log?.loggedAtHlc), 'export_generated_before_disclosure_log');
}

function evaluateHumanAuthorization(input, reasons) {
  const authorization = input?.humanAuthorization;
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_authorization_reviewer_absent');
  addReason(reasons, !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status), 'human_authorization_not_approved');
  addReason(reasons, !isDigest(authorization?.authorizationHash), 'human_authorization_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.authorizedAtHlc) === null, 'human_authorization_time_invalid');
  addReason(reasons, authorization?.aiFinalAuthorityRejected !== true, 'ai_final_authority_not_rejected');
  addReason(reasons, hlcBefore(authorization?.authorizedAtHlc, input?.exportControlPolicy?.evaluatedAtHlc), 'human_authorization_before_policy');
  addReason(
    reasons,
    hlcAfter(authorization?.authorizedAtHlc, input?.exportRequest?.generatedAtHlc),
    'human_authorization_after_export_generation',
  );
}

function evaluateAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined || ai?.used !== true) {
    return;
  }

  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_review_human_review_absent');
  addReason(reasons, !isDigest(ai.scopeHash), 'ai_scope_hash_invalid');
}

function consentByRef(input) {
  const entries = Array.isArray(input?.participantConsentMatrix) ? input.participantConsentMatrix : [];
  return new Map(entries.filter((entry) => hasText(entry?.consentRef)).map((entry) => [entry.consentRef, entry]));
}

function evaluateParticipantConsent(record, input, reasons) {
  if (record?.participantLinked !== true) {
    return true;
  }

  const recordRef = hasText(record?.recordRef) ? record.recordRef : 'unknown';
  const consent = consentByRef(input).get(record?.consentRef);

  addReason(reasons, !hasText(record?.consentRef), `participant_consent_ref_absent:${recordRef}`);
  addReason(reasons, consent === undefined, `participant_consent_absent:${recordRef}`);
  addReason(reasons, consent?.status !== 'active', `participant_consent_not_active:${recordRef}`);
  addReason(reasons, consent?.revoked === true, `participant_consent_revoked:${recordRef}`);
  addReason(reasons, consent?.scope !== 'export_metadata', `participant_consent_scope_invalid:${recordRef}`);
  addReason(reasons, !isDigest(consent?.participantCodeHash), `participant_consent_code_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(consent?.consentReceiptHash), `participant_consent_receipt_hash_invalid:${recordRef}`);
  addReason(reasons, hlcTuple(consent?.expiresAtHlc) === null, `participant_consent_expiry_invalid:${recordRef}`);
  addReason(reasons, hlcNotAfter(consent?.expiresAtHlc, input?.exportRequest?.generatedAtHlc), `participant_consent_expired:${recordRef}`);

  return (
    consent?.status === 'active' &&
    consent?.revoked !== true &&
    consent?.scope === 'export_metadata' &&
    isDigest(consent?.participantCodeHash) &&
    isDigest(consent?.consentReceiptHash) &&
    hlcTuple(consent?.expiresAtHlc) !== null &&
    hlcAfter(consent?.expiresAtHlc, input?.exportRequest?.generatedAtHlc)
  );
}

function validateRecord(record, input, reasons) {
  const recordRef = hasText(record?.recordRef) ? record.recordRef : 'unknown';
  addReason(reasons, !hasText(record?.recordRef), 'record_ref_absent');
  addReason(reasons, !hasText(record?.exportFamily), `record_export_family_absent:${recordRef}`);
  addReason(reasons, record?.exportType !== input?.exportRequest?.exportType, `record_export_type_mismatch:${recordRef}`);
  addReason(reasons, !hasText(record?.siteRef), `record_site_ref_absent:${recordRef}`);
  addReason(reasons, !isDigest(record?.artifactHash), `record_artifact_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.metadataHash), `record_metadata_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.custodyDigest), `record_custody_digest_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.accessLogHash), `record_access_log_hash_invalid:${recordRef}`);
  addReason(reasons, !CLASSIFICATIONS.has(record?.classification), `record_classification_invalid:${recordRef}`);
  addReason(reasons, sortedTextList(record?.sensitivityTags).length === 0, `record_sensitivity_tags_absent:${recordRef}`);
  addReason(reasons, sortedTextList(record?.allowedRoleRefs).length === 0, `record_allowed_roles_absent:${recordRef}`);
  addReason(reasons, sortedTextList(record?.recipientClasses).length === 0, `record_recipient_classes_absent:${recordRef}`);
  addReason(reasons, !hasText(record?.privacyCategory), `record_privacy_category_absent:${recordRef}`);
  addReason(reasons, !hasText(record?.confidentialityCategory), `record_confidentiality_category_absent:${recordRef}`);
  addReason(reasons, hlcTuple(record?.updatedAtHlc) === null, `record_updated_time_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.metadataOnly !== true, `record_metadata_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.rawContentExcluded !== true, `record_raw_content_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.sourcePayloadExcluded !== true, `record_source_payload_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.directIdentifiersExcluded !== true, `record_identifier_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.sponsorConfidentialContentExcluded !== true, `record_sponsor_confidential_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.privilegedContentExcluded !== true, `record_privileged_boundary_invalid:${recordRef}`);
}

function normalizeRecord(record) {
  return {
    accessLogHash: record.accessLogHash,
    artifactHash: record.artifactHash,
    classification: record.classification,
    confidentialityCategory: record.confidentialityCategory,
    custodyDigest: record.custodyDigest,
    exportFamily: record.exportFamily,
    metadataHash: record.metadataHash,
    participantLinked: record.participantLinked === true,
    privacyCategory: record.privacyCategory,
    recordRef: record.recordRef,
    sensitivityTags: sortedTextList(record.sensitivityTags),
    siteRef: record.siteRef,
    updatedAtHlc: record.updatedAtHlc,
  };
}

function recordAllowedByPolicy(record, input, consentReady) {
  const policy = input?.exportControlPolicy;
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const recordRoles = sortedTextList(record?.allowedRoleRefs);
  const recordRecipients = sortedTextList(record?.recipientClasses);
  const recordSensitivityTags = sortedTextList(record?.sensitivityTags);

  return (
    consentReady &&
    record?.exportType === input?.exportRequest?.exportType &&
    sortedTextList(policy?.allowedExportTypes).includes(record?.exportType) &&
    sortedTextList(policy?.allowedRecipientClasses).includes(input?.exportRequest?.recipientClass) &&
    recordRecipients.includes(input?.exportRequest?.recipientClass) &&
    textListsIntersect(recordRoles, actorRoles) &&
    textListsIntersect(recordRoles, sortedTextList(policy?.allowedRoleRefs)) &&
    includesAll(recordSensitivityTags, sortedTextList(policy?.allowedSensitivityTags)) &&
    sortedTextList(policy?.allowedPrivacyCategories).includes(record?.privacyCategory) &&
    sortedTextList(policy?.allowedConfidentialityCategories).includes(record?.confidentialityCategory)
  );
}

function normalizeRecords(input, reasons) {
  const records = Array.isArray(input?.records) ? input.records : [];
  addReason(reasons, records.length === 0, 'export_records_absent');

  const permissionByRef = new Map();
  for (const record of records) {
    validateRecord(record, input, reasons);
    permissionByRef.set(record?.recordRef, evaluateParticipantConsent(record, input, reasons));
  }

  const permitted = records
    .filter((record) => recordAllowedByPolicy(record, input, permissionByRef.get(record?.recordRef) === true))
    .map(normalizeRecord)
    .sort(
      (left, right) =>
        left.exportFamily.localeCompare(right.exportFamily) ||
        left.recordRef.localeCompare(right.recordRef),
    );

  const permittedKeys = new Set(permitted.map((record) => `${record.exportFamily}:${record.recordRef}`));
  const validRecords = records.filter((record) => hasText(record?.recordRef) && hasText(record?.exportFamily));
  const suppressedRecordCount = validRecords.filter(
    (record) => !permittedKeys.has(`${record.exportFamily}:${record.recordRef}`),
  ).length;

  addReason(reasons, permitted.length === 0, 'permitted_export_records_absent');

  return { permitted, suppressedRecordCount };
}

function requiresSponsorCroRequestLinkage(input) {
  return (
    input?.exportRequest?.purpose === 'sponsor_diligence' ||
    input?.exportRequest?.exportType === 'sponsor_diligence_packet'
  );
}

function evaluateResponsePackage(input, records, required, reasons) {
  const responsePackage = input?.responsePackage;
  if (!required && (responsePackage === null || responsePackage === undefined)) {
    return null;
  }

  const packageRecordRefs = sortedTextList(responsePackage?.packageRecordRefs);
  const exportedRecordRefs = sortedTextList(records.map((record) => record.recordRef));

  addReason(reasons, responsePackage === null || responsePackage === undefined, 'sponsor_cro_response_package_absent');
  addReason(reasons, !hasText(responsePackage?.packageRef), 'sponsor_cro_response_package_ref_absent');
  addReason(reasons, !isDigest(responsePackage?.packageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(
    reasons,
    responsePackage?.requestRef !== input?.sponsorCroRequestEvidence?.requestRef,
    'sponsor_cro_response_package_request_mismatch',
  );
  addReason(
    reasons,
    responsePackage?.workItemRef !== input?.sponsorCroRequestEvidence?.workItemRef,
    'sponsor_cro_response_package_work_item_mismatch',
  );
  addReason(
    reasons,
    responsePackage?.recipientTenantId !== input?.exportRequest?.recipientTenantId,
    'sponsor_cro_response_package_recipient_mismatch',
  );
  addReason(
    reasons,
    !sameTextSet(packageRecordRefs, exportedRecordRefs),
    'sponsor_cro_response_package_record_scope_mismatch',
  );
  addReason(reasons, hlcTuple(responsePackage?.generatedAtHlc) === null, 'sponsor_cro_response_package_time_invalid');
  addReason(
    reasons,
    hlcAfter(responsePackage?.generatedAtHlc, input?.exportRequest?.generatedAtHlc),
    'sponsor_cro_response_package_after_export_generation',
  );
  addReason(
    reasons,
    responsePackage?.metadataOnly !== true,
    'sponsor_cro_response_package_metadata_boundary_invalid',
  );
  addReason(
    reasons,
    responsePackage?.rawContentExcluded !== true,
    'sponsor_cro_response_package_raw_content_boundary_invalid',
  );
  addReason(
    reasons,
    responsePackage?.protectedContentExcluded !== true,
    'sponsor_cro_response_package_protected_boundary_invalid',
  );

  return {
    generatedAtHlc: responsePackage?.generatedAtHlc ?? null,
    packageHash: hasText(responsePackage?.packageHash) ? responsePackage.packageHash : null,
    packageRecordRefs,
    packageRef: hasText(responsePackage?.packageRef) ? responsePackage.packageRef : null,
    recipientTenantId: hasText(responsePackage?.recipientTenantId) ? responsePackage.recipientTenantId : null,
    requestRef: hasText(responsePackage?.requestRef) ? responsePackage.requestRef : null,
    workItemRef: hasText(responsePackage?.workItemRef) ? responsePackage.workItemRef : null,
  };
}

function evaluateSponsorCroRequestEvidence(input, responsePackage, required, reasons) {
  const evidence = input?.sponsorCroRequestEvidence;
  if (!required && (evidence === null || evidence === undefined)) {
    return null;
  }

  addReason(reasons, evidence === null || evidence === undefined, 'sponsor_cro_request_evidence_absent');
  addReason(reasons, !hasText(evidence?.requestRef), 'sponsor_cro_request_ref_absent');
  addReason(reasons, !isDigest(evidence?.requestHash), 'sponsor_cro_request_hash_invalid');
  addReason(
    reasons,
    !SPONSOR_CRO_REQUESTER_CLASSES.has(evidence?.requesterClass),
    'sponsor_cro_requester_class_invalid',
  );
  addReason(reasons, !hasText(evidence?.workItemRef), 'sponsor_cro_work_item_ref_absent');
  addReason(
    reasons,
    !SPONSOR_CRO_WORK_ITEM_STATUSES.has(evidence?.workItemStatus),
    'sponsor_cro_work_item_status_invalid',
  );
  addReason(reasons, !hasText(evidence?.disclosureEventRef), 'sponsor_cro_disclosure_event_ref_absent');
  addReason(reasons, !isDigest(evidence?.disclosureLogHash), 'sponsor_cro_disclosure_log_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.disclosureLogHash) && evidence.disclosureLogHash !== input?.disclosureLog?.disclosureLogHash,
    'sponsor_cro_disclosure_log_hash_mismatch',
  );
  addReason(reasons, !hasText(evidence?.decisionForumMatterRef), 'sponsor_cro_decision_forum_matter_absent');
  addReason(reasons, !isDigest(evidence?.humanReviewHash), 'sponsor_cro_human_review_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.humanReviewHash) && evidence.humanReviewHash !== input?.humanAuthorization?.authorizationHash,
    'sponsor_cro_human_review_hash_mismatch',
  );
  addReason(reasons, !isDigest(evidence?.responsePackageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.responsePackageHash) && evidence.responsePackageHash !== responsePackage?.packageHash,
    'sponsor_cro_response_package_hash_mismatch',
  );
  addReason(
    reasons,
    evidence?.linkedRecipientTenantId !== input?.exportRequest?.recipientTenantId,
    'sponsor_cro_request_recipient_mismatch',
  );
  addReason(reasons, evidence?.linkedExportRef !== input?.exportRequest?.exportRef, 'sponsor_cro_linked_export_mismatch');
  addReason(reasons, evidence?.metadataOnly !== true, 'sponsor_cro_request_metadata_boundary_invalid');
  addReason(
    reasons,
    evidence?.sourcePayloadExcluded !== true,
    'sponsor_cro_request_source_payload_boundary_invalid',
  );
  addReason(
    reasons,
    evidence?.protectedContentExcluded !== true,
    'sponsor_cro_request_protected_boundary_invalid',
  );
  addReason(reasons, evidence?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(evidence?.linkedAtHlc) === null, 'sponsor_cro_request_link_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.linkedAtHlc, input?.exportRequest?.generatedAtHlc),
    'sponsor_cro_request_link_after_export_generation',
  );

  return {
    decisionForumMatterRef: hasText(evidence?.decisionForumMatterRef) ? evidence.decisionForumMatterRef : null,
    disclosureEventRef: hasText(evidence?.disclosureEventRef) ? evidence.disclosureEventRef : null,
    disclosureLogHash: hasText(evidence?.disclosureLogHash) ? evidence.disclosureLogHash : null,
    humanReviewHash: hasText(evidence?.humanReviewHash) ? evidence.humanReviewHash : null,
    linkedAtHlc: evidence?.linkedAtHlc ?? null,
    linkedExportRef: hasText(evidence?.linkedExportRef) ? evidence.linkedExportRef : null,
    linkedRecipientTenantId: hasText(evidence?.linkedRecipientTenantId) ? evidence.linkedRecipientTenantId : null,
    requestHash: hasText(evidence?.requestHash) ? evidence.requestHash : null,
    requesterClass: hasText(evidence?.requesterClass) ? evidence.requesterClass : null,
    requestRef: hasText(evidence?.requestRef) ? evidence.requestRef : null,
    responsePackageHash: hasText(evidence?.responsePackageHash) ? evidence.responsePackageHash : null,
    workItemRef: hasText(evidence?.workItemRef) ? evidence.workItemRef : null,
    workItemStatus: hasText(evidence?.workItemStatus) ? evidence.workItemStatus : null,
  };
}

function optionalTextList(value) {
  return hasText(value) ? [value] : [];
}

function buildPackage(input, records, suppressedRecordCount, sponsorCroRequestEvidence, responsePackage) {
  const controlDomains = [...REQUIRED_CONTROL_DOMAINS].sort();
  const packageHash = sha256Hex({
    actorDid: input.actor.did,
    controlDomains,
    exportRef: input.exportRequest.exportRef,
    exportType: input.exportRequest.exportType,
    generatedAtHlc: input.exportRequest.generatedAtHlc,
    records,
    recipientClass: input.exportRequest.recipientClass,
    recipientTenantId: input.exportRequest.recipientTenantId,
    responsePackage,
    schema: EXPORT_CONTROL_SCHEMA,
    sponsorCroRequestEvidence,
    suppressedRecordCount,
    tenantId: input.tenantId,
  });

  return {
    schema: EXPORT_CONTROL_SCHEMA,
    packageId: `cmec_${packageHash.slice(0, 32)}`,
    packageHash,
    exportRef: input.exportRequest.exportRef,
    exportType: input.exportRequest.exportType,
    controlDomains,
    recordCount: records.length,
    suppressedRecordCount,
    records,
    exportControlsApplied: true,
    privacyBoundarySatisfied: records.every((record) => hasText(record.privacyCategory)),
    confidentialityBoundarySatisfied: records.every((record) => hasText(record.confidentialityCategory)),
    accessBoundarySatisfied: records.every((record) => isDigest(record.accessLogHash)),
    disclosureLogged: isDigest(input.disclosureLog.disclosureLogHash),
    responsePackageHash: responsePackage?.packageHash ?? null,
    responsePackageRef: responsePackage?.packageRef ?? null,
    sponsorCroRequestRefs: optionalTextList(sponsorCroRequestEvidence?.requestRef),
    sponsorCroWorkItemRefs: optionalTextList(sponsorCroRequestEvidence?.workItemRef),
    controlledRequestEvidence: sponsorCroRequestEvidence,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, controlPackage) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'export_control_package',
    artifactVersion: `${input.exportRequest.exportRef}:${input.exportRequest.generatedAtHlc.physicalMs}.${input.exportRequest.generatedAtHlc.logical}`,
    artifactHash: controlPackage.packageHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.exportRequest.generatedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['export_control', 'metadata_only', 'privacy_confidentiality_access'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateExportControl(input) {
  assertMetadataOnly(input);
  const reasons = [];

  evaluateTenantActorAuthority(input, reasons);
  evaluateExportRequest(input, reasons);
  evaluateExportControlPolicy(input, reasons);
  evaluateDisclosureLog(input, reasons);
  evaluateHumanAuthorization(input, reasons);
  evaluateAiAssistance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const { permitted, suppressedRecordCount } = normalizeRecords(input, reasons);
  const sponsorCroLinkageRequired = requiresSponsorCroRequestLinkage(input);
  const responsePackage = evaluateResponsePackage(input, permitted, sponsorCroLinkageRequired, reasons);
  const sponsorCroRequestEvidence = evaluateSponsorCroRequestEvidence(
    input,
    responsePackage,
    sponsorCroLinkageRequired,
    reasons,
  );
  const controlPackage = buildPackage(
    input,
    permitted,
    suppressedRecordCount,
    sponsorCroRequestEvidence,
    responsePackage,
  );
  const denied = reasons.length > 0;

  return {
    schema: EXPORT_CONTROL_SCHEMA,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: uniqueReasons(reasons),
    tenantId: input?.tenantId ?? null,
    targetTenantId: input?.targetTenantId ?? null,
    controlPackage,
    receipt: denied ? null : buildReceipt(input, controlPackage),
  };
}
