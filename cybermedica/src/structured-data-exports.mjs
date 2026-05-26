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
const STRUCTURED_EXPORT_SCHEMA = 'cybermedica.structured_data_export.v1';
const REQUIRED_PERMISSION = 'data_export';
const REQUIRED_EXPORT_FAMILIES = new Set(['audit_record', 'diligence_packet', 'evidence_index', 'site_data']);
const EXPORT_FORMATS = new Set(['csv', 'json', 'markdown']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const EXPORT_GRANT_SCOPES = new Set(['structured_data_export']);
const EXPORT_GRANT_STATUSES = new Set(['active']);
const ACCESS_POLICY_STATUSES = new Set(['active']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);
const CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'confidential_metadata_only',
  'qms_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);

const RAW_STRUCTURED_EXPORT_FIELDS = new Set([
  'auditrecordbody',
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
  'rawevidenceindex',
  'rawexport',
  'rawrecord',
  'rawsite',
  'rawsitedata',
  'rawsource',
  'rawsourcedata',
  'recordbody',
  'sitebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_STRUCTURED_EXPORT_FIELDS = new Set([
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

function assertNoRawStructuredExportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawStructuredExportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_STRUCTURED_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw structured export content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_STRUCTURED_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`structured export secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawStructuredExportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawStructuredExportContent(input ?? {});
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

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function includesAll(needles, haystack) {
  const haystackSet = new Set(haystack);
  return needles.every((needle) => haystackSet.has(needle));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function textListsIntersect(left, right) {
  const rightSet = new Set(right);
  return left.some((item) => rightSet.has(item));
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'export_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateExportGrant(input, reasons) {
  const grant = input?.exportGrant;
  const request = input?.exportRequest;
  addReason(reasons, !hasText(grant?.grantRef), 'export_grant_ref_absent');
  addReason(reasons, !isDigest(grant?.grantHash), 'export_grant_hash_invalid');
  addReason(reasons, !EXPORT_GRANT_STATUSES.has(grant?.status), 'export_grant_not_active');
  addReason(reasons, !EXPORT_GRANT_SCOPES.has(grant?.scope), 'export_grant_scope_invalid');
  addReason(reasons, grant?.recipientTenantId !== request?.recipientTenantId, 'export_grant_recipient_mismatch');
  addReason(reasons, hlcTuple(grant?.expiresAtHlc) === null, 'export_grant_expiry_invalid');
  addReason(
    reasons,
    hlcBefore(grant?.expiresAtHlc, request?.generatedAtHlc) || compareHlcTuple(hlcTuple(grant?.expiresAtHlc) ?? [0, 0], hlcTuple(request?.generatedAtHlc) ?? [1, 0]) === 0,
    'export_grant_expired',
  );
}

function evaluateExportRequest(input, requestedFamilies, reasons) {
  const request = input?.exportRequest;
  addReason(reasons, !hasText(request?.exportRef), 'export_ref_absent');
  addReason(reasons, !hasText(request?.purpose), 'export_purpose_absent');
  addReason(reasons, !hasText(request?.recipientTenantId), 'export_recipient_tenant_absent');
  addReason(reasons, !hasText(request?.recipientClass), 'export_recipient_class_absent');
  addReason(reasons, !EXPORT_FORMATS.has(request?.requestedFormat), 'export_format_invalid');
  addReason(reasons, request?.metadataOnly !== true, 'export_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'export_requested_time_invalid');
  addReason(reasons, hlcTuple(request?.generatedAtHlc) === null, 'export_generated_time_invalid');
  addReason(reasons, hlcBefore(request?.generatedAtHlc, request?.requestedAtHlc), 'export_generated_before_request');
  addReason(reasons, requestedFamilies.length === 0, 'export_families_absent');

  for (const family of requestedFamilies) {
    addReason(reasons, !REQUIRED_EXPORT_FAMILIES.has(family), `export_family_unsupported:${family}`);
  }
  for (const family of [...REQUIRED_EXPORT_FAMILIES].sort()) {
    addReason(reasons, !requestedFamilies.includes(family), `required_export_family_not_requested:${family}`);
  }
}

function evaluateAccessPolicy(input, requestedFamilies, reasons) {
  const policy = input?.accessPolicy;
  const allowedFamilies = sortedTextList(policy?.allowedFamilies);
  addReason(reasons, !hasText(policy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'access_policy_hash_invalid');
  addReason(reasons, !ACCESS_POLICY_STATUSES.has(policy?.status), 'access_policy_not_active');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'access_policy_time_invalid');
  addReason(reasons, sortedTextList(policy?.allowedSiteRefs).length === 0, 'access_policy_site_refs_absent');
  addReason(reasons, sortedTextList(policy?.allowedRoleRefs).length === 0, 'access_policy_roles_absent');
  addReason(reasons, sortedTextList(policy?.allowedRecipientClasses).length === 0, 'access_policy_recipient_classes_absent');
  addReason(reasons, sortedTextList(policy?.allowedSensitivityTags).length === 0, 'access_policy_sensitivity_tags_absent');
  addReason(reasons, policy?.sourcePayloadAccessible !== false, 'access_policy_payload_access_forbidden');
  addReason(reasons, policy?.metadataOnly !== true, 'access_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'access_policy_disclosure_required_absent');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcBefore(policy?.evaluatedAtHlc, input?.exportRequest?.requestedAtHlc), 'access_policy_before_request');

  for (const family of requestedFamilies) {
    addReason(reasons, !allowedFamilies.includes(family), `requested_family_not_allowed:${family}`);
  }
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, log?.purpose !== input?.exportRequest?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, log?.recipientClass !== input?.exportRequest?.recipientClass, 'disclosure_log_recipient_mismatch');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.accessPolicy?.evaluatedAtHlc), 'disclosure_log_before_access_policy');
  addReason(reasons, hlcBefore(input?.exportRequest?.generatedAtHlc, log?.loggedAtHlc), 'export_generated_before_disclosure_log');
}

function evaluateHumanAuthorization(input, reasons) {
  const authorization = input?.humanAuthorization;
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_authorization_reviewer_absent');
  addReason(reasons, !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status), 'human_authorization_not_approved');
  addReason(reasons, !isDigest(authorization?.authorizationHash), 'human_authorization_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.authorizedAtHlc) === null, 'human_authorization_time_invalid');
  addReason(reasons, authorization?.aiFinalAuthorityRejected !== true, 'ai_final_authority_not_rejected');
  addReason(
    reasons,
    hlcAfter(authorization?.authorizedAtHlc, input?.exportRequest?.generatedAtHlc),
    'human_authorization_after_export_generation',
  );
  addReason(
    reasons,
    hlcBefore(authorization?.authorizedAtHlc, input?.accessPolicy?.evaluatedAtHlc),
    'human_authorization_before_access_policy',
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
  addReason(reasons, sortedTextList(ai.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !Array.isArray(ai.limitationHashes), 'ai_limitation_hashes_invalid');
  for (const limitationHash of Array.isArray(ai.limitationHashes) ? ai.limitationHashes : []) {
    addReason(reasons, !isDigest(limitationHash), 'ai_limitation_hash_invalid');
  }
}

function validateRecord(record, reasons) {
  const recordRef = hasText(record?.recordRef) ? record.recordRef : 'unknown';
  addReason(reasons, !hasText(record?.recordRef), 'record_ref_absent');
  addReason(reasons, !REQUIRED_EXPORT_FAMILIES.has(record?.family), `record_family_unsupported:${recordRef}`);
  addReason(reasons, !hasText(record?.siteRef), `record_site_ref_absent:${recordRef}`);
  addReason(reasons, !isDigest(record?.artifactHash), `record_artifact_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.metadataHash), `record_metadata_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.provenanceHash), `record_provenance_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.custodyDigest), `record_custody_digest_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.accessLogHash), `record_access_log_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.decisionRationaleHash), `record_decision_rationale_hash_invalid:${recordRef}`);
  addReason(reasons, !isDigest(record?.versionHistoryHash), `record_version_history_hash_invalid:${recordRef}`);
  addReason(reasons, !hasText(record?.retentionRuleRef), `record_retention_rule_absent:${recordRef}`);
  addReason(reasons, !CLASSIFICATIONS.has(record?.classification), `record_classification_invalid:${recordRef}`);
  addReason(reasons, sortedTextList(record?.sensitivityTags).length === 0, `record_sensitivity_tags_absent:${recordRef}`);
  addReason(reasons, sortedTextList(record?.allowedRoleRefs).length === 0, `record_allowed_roles_absent:${recordRef}`);
  addReason(reasons, sortedTextList(record?.recipientClasses).length === 0, `record_recipient_classes_absent:${recordRef}`);
  addReason(reasons, hlcTuple(record?.updatedAtHlc) === null, `record_updated_time_invalid:${recordRef}`);
  addReason(reasons, record?.exportable !== true, `record_not_exportable:${recordRef}`);
  addReason(reasons, record?.boundary?.metadataOnly !== true, `record_metadata_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.rawContentExcluded !== true, `record_raw_content_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.sourcePayloadExcluded !== true, `record_source_payload_boundary_invalid:${recordRef}`);
  addReason(reasons, record?.boundary?.directIdentifiersExcluded !== true, `record_identifier_boundary_invalid:${recordRef}`);
}

function normalizeRecord(record) {
  return {
    accessLogHash: record.accessLogHash,
    artifactHash: record.artifactHash,
    classification: record.classification,
    custodyDigest: record.custodyDigest,
    decisionRationaleHash: record.decisionRationaleHash,
    family: record.family,
    metadataHash: record.metadataHash,
    provenanceHash: record.provenanceHash,
    recordRef: record.recordRef,
    retentionRuleRef: record.retentionRuleRef,
    sensitivityTags: sortedTextList(record.sensitivityTags),
    siteRef: record.siteRef,
    updatedAtHlc: record.updatedAtHlc,
    versionHistoryHash: record.versionHistoryHash,
  };
}

function recordAllowedByPolicy(record, input) {
  const policy = input?.accessPolicy;
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const recordRoles = sortedTextList(record?.allowedRoleRefs);
  const recordRecipients = sortedTextList(record?.recipientClasses);
  const recordSensitivityTags = sortedTextList(record?.sensitivityTags);

  return (
    sortedTextList(policy?.allowedFamilies).includes(record?.family) &&
    sortedTextList(policy?.allowedSiteRefs).includes(record?.siteRef) &&
    sortedTextList(policy?.allowedRecipientClasses).includes(input?.exportRequest?.recipientClass) &&
    recordRecipients.includes(input?.exportRequest?.recipientClass) &&
    textListsIntersect(recordRoles, actorRoles) &&
    textListsIntersect(recordRoles, sortedTextList(policy?.allowedRoleRefs)) &&
    includesAll(recordSensitivityTags, sortedTextList(policy?.allowedSensitivityTags))
  );
}

function normalizeRecords(input, requestedFamilies, reasons) {
  const records = Array.isArray(input?.records) ? input.records : [];
  addReason(reasons, records.length === 0, 'export_records_absent');

  for (const record of records) {
    validateRecord(record, reasons);
  }

  const permitted = records
    .filter((record) => recordAllowedByPolicy(record, input))
    .map(normalizeRecord)
    .sort(
      (left, right) =>
        left.family.localeCompare(right.family) ||
        left.recordRef.localeCompare(right.recordRef),
    );

  const permittedKeys = new Set(permitted.map((record) => `${record.family}:${record.recordRef}`));
  const validRecords = records.filter((record) => hasText(record?.recordRef) && REQUIRED_EXPORT_FAMILIES.has(record?.family));
  const suppressedRecordCount = validRecords.filter((record) => !permittedKeys.has(`${record.family}:${record.recordRef}`)).length;
  const permittedFamilies = uniqueSorted(permitted.map((record) => record.family));

  for (const family of requestedFamilies) {
    addReason(reasons, !permittedFamilies.includes(family), `required_family_missing:${family}`);
  }

  return { permitted, permittedFamilies, suppressedRecordCount };
}

function buildPackage(input, records, exportFamilies, suppressedRecordCount) {
  const packageHash = sha256Hex({
    actorDid: input.actor.did,
    exportRef: input.exportRequest.exportRef,
    exportFamilies,
    generatedAtHlc: input.exportRequest.generatedAtHlc,
    records,
    recipientClass: input.exportRequest.recipientClass,
    recipientTenantId: input.exportRequest.recipientTenantId,
    schema: STRUCTURED_EXPORT_SCHEMA,
    suppressedRecordCount,
    tenantId: input.tenantId,
  });

  return {
    schema: STRUCTURED_EXPORT_SCHEMA,
    packageId: `cmsde_${packageHash.slice(0, 32)}`,
    packageHash,
    exportRef: input.exportRequest.exportRef,
    exportFamilies,
    recordCount: records.length,
    suppressedRecordCount,
    records,
    structuredExportSubjectToAccessPolicy: true,
    provenancePreserved: records.every((record) => isDigest(record.provenanceHash)),
    custodyPreserved: records.every((record) => isDigest(record.custodyDigest)),
    timestampsPreserved: records.every((record) => hlcTuple(record.updatedAtHlc) !== null),
    accessLogsPreserved: records.every((record) => isDigest(record.accessLogHash)),
    decisionRationalePreserved: records.every((record) => isDigest(record.decisionRationaleHash)),
    versionHistoryPreserved: records.every((record) => isDigest(record.versionHistoryHash)),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, exportPackage) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'structured_data_export',
    artifactVersion: `${input.exportRequest.exportRef}@${input.exportRequest.generatedAtHlc.physicalMs}.${input.exportRequest.generatedAtHlc.logical}`,
    artifactHash: exportPackage.packageHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.exportRequest.generatedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['structured_export', 'metadata_only', 'access_policy_bound'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateStructuredDataExport(input) {
  assertMetadataOnly(input);
  const reasons = [];
  const requestedFamilies = sortedTextList(input?.exportRequest?.requestedFamilies);

  evaluateTenantActorAuthority(input, reasons);
  evaluateExportRequest(input, requestedFamilies, reasons);
  evaluateExportGrant(input, reasons);
  evaluateAccessPolicy(input, requestedFamilies, reasons);
  evaluateDisclosureLog(input, reasons);
  evaluateHumanAuthorization(input, reasons);
  evaluateAiAssistance(input, reasons);

  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const { permitted, permittedFamilies, suppressedRecordCount } = normalizeRecords(input, requestedFamilies, reasons);
  const exportFamilies = uniqueSorted(permittedFamilies);
  const exportPackage = buildPackage(input, permitted, exportFamilies, suppressedRecordCount);
  const denied = reasons.length > 0;

  return {
    schema: STRUCTURED_EXPORT_SCHEMA,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: uniqueReasons(reasons),
    tenantId: input?.tenantId ?? null,
    targetTenantId: input?.targetTenantId ?? null,
    exportPackage,
    receipt: denied ? null : buildReceipt(input, exportPackage),
  };
}
