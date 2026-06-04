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
const DECISION_SCHEMA = 'cybermedica.study_scope_isolation_decision.v1';
const ACCESS_SCHEMA = 'cybermedica.study_scope_isolation.v1';
const EXPORT_SCOPE = 'study_sponsor_cro_export';
const OPERATIONS = new Set(['export', 'read', 'write']);
const REQUIRED_PERMISSION = Object.freeze({
  export: 'read',
  read: 'read',
  write: 'write',
});
const RESOURCE_CLASSIFICATIONS = new Set([
  'sponsor_cro_confidential_metadata_only',
  'study_scoped_metadata_only',
]);

const SECRET_STUDY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
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

function assertNoStudySecretMaterial(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoStudySecretMaterial(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (SECRET_STUDY_FIELDS.has(normalizeFieldName(key)) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`study scope secret field is not allowed at ${path}.${key}`);
    }
    assertNoStudySecretMaterial(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoStudySecretMaterial(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function normalizeStudy(record) {
  if (record === null || typeof record !== 'object') {
    return null;
  }
  return {
    allowedOperations: sortedTextList(record.allowedOperations),
    confidentialityClass: record.confidentialityClass,
    croTenantId: record.croTenantId,
    protocolRefs: sortedTextList(record.protocolRefs),
    registryEvidenceHash: record.registryEvidenceHash,
    siteId: record.siteId,
    sponsorTenantId: record.sponsorTenantId,
    status: record.status,
    studyId: record.studyId,
    tenantId: record.tenantId,
  };
}

function studyRegistryRecords(registry) {
  if (!Array.isArray(registry)) {
    return [];
  }
  return registry.map(normalizeStudy).filter((record) => record !== null).sort((left, right) => {
    return String(left.studyId).localeCompare(String(right.studyId));
  });
}

function findStudy(registry, studyId) {
  return studyRegistryRecords(registry).find((record) => record.studyId === studyId) ?? null;
}

function studyActive(record) {
  return record !== null && record.status === 'active';
}

function studyAllows(record, operation) {
  return Array.isArray(record?.allowedOperations) && record.allowedOperations.includes(operation);
}

function evaluateRequestShape(input, reasons) {
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !OPERATIONS.has(input?.operation), 'operation_invalid');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, !hasText(input?.siteId), 'site_absent');
  addReason(reasons, !hasText(input?.studyId), 'study_absent');
  addReason(reasons, !hasText(input?.targetStudyId), 'target_study_absent');
  addReason(reasons, input?.studyId !== input?.targetStudyId, 'study_boundary_violation');
  addReason(reasons, !hasText(input?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, hlcTuple(input?.requestedAtHlc) === null, 'requested_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function evaluateStudyRegistry(input, reasons) {
  const requestedStudy = findStudy(input?.studyRegistry, input?.studyId);
  const targetStudy = findStudy(input?.studyRegistry, input?.targetStudyId);
  const targetProtocolRefs = sortedTextList(targetStudy?.protocolRefs);

  addReason(reasons, !Array.isArray(input?.studyRegistry) || input.studyRegistry.length === 0, 'study_registry_absent');
  addReason(reasons, requestedStudy === null, 'study_registry_record_absent');
  addReason(reasons, targetStudy === null, 'target_study_registry_record_absent');
  addReason(reasons, requestedStudy !== null && !studyActive(requestedStudy), 'study_not_active');
  addReason(reasons, targetStudy !== null && !studyActive(targetStudy), 'target_study_not_active');
  addReason(reasons, requestedStudy !== null && requestedStudy.tenantId !== input?.tenantId, 'study_tenant_mismatch');
  addReason(reasons, requestedStudy !== null && requestedStudy.siteId !== input?.siteId, 'study_site_mismatch');
  addReason(reasons, targetStudy !== null && targetStudy.tenantId !== input?.tenantId, 'target_study_tenant_mismatch');
  addReason(reasons, targetStudy !== null && targetStudy.siteId !== input?.siteId, 'target_study_site_mismatch');
  addReason(reasons, requestedStudy !== null && !studyAllows(requestedStudy, input?.operation), 'study_operation_not_allowed');
  addReason(reasons, targetStudy !== null && !studyAllows(targetStudy, input?.operation), 'target_study_operation_not_allowed');
  addReason(reasons, targetStudy !== null && !targetProtocolRefs.includes(input?.protocolRef), 'protocol_not_in_requested_study');
  addReason(reasons, requestedStudy !== null && !isDigest(requestedStudy.registryEvidenceHash), 'study_registry_evidence_hash_invalid');
  addReason(reasons, targetStudy !== null && !isDigest(targetStudy.registryEvidenceHash), 'target_study_registry_evidence_hash_invalid');

  return { requestedStudy, targetStudy };
}

function evaluateActorScope(input, reasons) {
  const siteAssignments = sortedTextList(input?.actor?.siteAssignments);
  const studyAssignments = sortedTextList(input?.actor?.studyAssignments);
  const protocolAssignments = sortedTextList(input?.actor?.protocolAssignments);

  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai', 'ai_actor_cannot_authorize_study_access');
  addReason(reasons, input?.actor?.tenantId !== input?.tenantId, 'actor_tenant_mismatch');
  addReason(reasons, !siteAssignments.includes(input?.siteId), 'actor_site_assignment_missing');
  addReason(reasons, !studyAssignments.includes(input?.studyId), 'actor_study_assignment_missing');
  addReason(reasons, !studyAssignments.includes(input?.targetStudyId), 'actor_target_study_assignment_missing');
  addReason(reasons, !protocolAssignments.includes(input?.protocolRef), 'actor_protocol_assignment_missing');
}

function evaluateAuthority(input, reasons) {
  const requiredPermission = REQUIRED_PERMISSION[input?.operation];
  const permissions = sortedTextList(input?.authority?.permissions);
  const scopeStudyIds = sortedTextList(input?.authority?.scope?.studyIds);
  const scopeProtocolRefs = sortedTextList(input?.authority?.scope?.protocolRefs);

  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasText(requiredPermission) || !permissions.includes(requiredPermission), 'authority_permission_missing');
  addReason(reasons, input?.authority?.scope?.tenantId !== input?.tenantId, 'authority_tenant_scope_mismatch');
  addReason(reasons, input?.authority?.scope?.siteId !== input?.siteId, 'authority_site_scope_mismatch');
  addReason(reasons, !scopeStudyIds.includes(input?.studyId), 'authority_study_scope_missing');
  addReason(reasons, !scopeStudyIds.includes(input?.targetStudyId), 'authority_target_study_scope_missing');
  addReason(reasons, !scopeProtocolRefs.includes(input?.protocolRef), 'authority_protocol_scope_missing');
}

function evaluateResource(input, reasons) {
  addReason(reasons, !hasText(input?.resource?.resourceId), 'resource_id_absent');
  addReason(reasons, !hasText(input?.resource?.resourceType), 'resource_type_absent');
  addReason(reasons, input?.resource?.tenantId !== input?.tenantId, 'resource_tenant_mismatch');
  addReason(reasons, input?.resource?.siteId !== input?.siteId, 'resource_site_mismatch');
  addReason(reasons, input?.resource?.studyId !== input?.targetStudyId, 'resource_study_mismatch');
  addReason(reasons, input?.resource?.protocolRef !== input?.protocolRef, 'resource_protocol_mismatch');
  addReason(reasons, !isDigest(input?.resource?.artifactHash), 'resource_artifact_hash_invalid');
  addReason(reasons, !RESOURCE_CLASSIFICATIONS.has(input?.resource?.classification), 'resource_classification_invalid');
}

function evaluatePrivacyBoundary(input, reasons) {
  const boundary = input?.privacyBoundary;
  addReason(reasons, boundary?.metadataOnly !== true, 'privacy_metadata_only_boundary_absent');
  addReason(reasons, boundary?.rawProtectedContentExcluded !== true, 'raw_protected_content_boundary_absent');
  addReason(reasons, boundary?.sponsorConfidentialPayloadExcluded !== true, 'sponsor_confidential_boundary_absent');
  addReason(reasons, boundary?.directIdentifiersExcluded !== true, 'direct_identifier_boundary_absent');
  addReason(reasons, boundary?.receiptPayloadMinimal !== true, 'receipt_payload_minimal_boundary_absent');
}

function evaluateExportConsent(input, reasons) {
  if (input?.operation !== 'export' || input?.resource?.participantLinked !== true) {
    return;
  }

  addReason(reasons, input?.consent === null || input?.consent === undefined, 'export_consent_absent');
  addReason(reasons, input?.consent?.status !== 'active', 'export_consent_not_active');
  addReason(reasons, input?.consent?.revoked === true || input?.consent?.status === 'revoked', 'export_consent_revoked');
  addReason(reasons, input?.consent?.studyId !== input?.studyId, 'export_consent_study_mismatch');
  addReason(reasons, !hasText(input?.consent?.consentRef), 'export_consent_ref_absent');
  addReason(reasons, !isDigest(input?.consent?.participantCodeHash), 'export_consent_participant_code_hash_invalid');
}

function evaluateVisibilityGrant(input, studyState, reasons) {
  if (input?.operation !== 'export') {
    return;
  }

  const authorizedRecipients = sortedTextList([
    studyState.requestedStudy?.croTenantId,
    studyState.requestedStudy?.sponsorTenantId,
  ]);
  const grant = input?.visibilityGrant;

  addReason(reasons, !hasText(input?.recipientTenantId), 'recipient_tenant_absent');
  addReason(
    reasons,
    hasText(input?.recipientTenantId) && !authorizedRecipients.includes(input.recipientTenantId),
    'recipient_not_authorized_for_study',
  );
  addReason(reasons, !hasText(grant?.grantId), 'visibility_grant_id_absent');
  addReason(reasons, grant?.status !== 'active', 'visibility_grant_not_active');
  addReason(reasons, grant?.scope !== EXPORT_SCOPE, 'visibility_grant_scope_invalid');
  addReason(reasons, grant?.sourceTenantId !== input?.tenantId, 'visibility_grant_source_tenant_mismatch');
  addReason(reasons, grant?.studyId !== input?.studyId, 'visibility_grant_study_mismatch');
  addReason(reasons, grant?.recipientTenantId !== input?.recipientTenantId, 'visibility_grant_recipient_mismatch');
  addReason(reasons, hlcTuple(grant?.approvedAtHlc) === null, 'visibility_grant_approval_time_invalid');
  addReason(reasons, hlcAfter(grant?.approvedAtHlc, input?.requestedAtHlc), 'visibility_grant_after_request');
  addReason(reasons, !isDigest(grant?.grantHash), 'visibility_grant_hash_invalid');
}

function validateInput(input, reasons) {
  assertMetadataOnly(input);
  evaluateRequestShape(input, reasons);
  const studyState = evaluateStudyRegistry(input, reasons);
  evaluateActorScope(input, reasons);
  evaluateAuthority(input, reasons);
  evaluateResource(input, reasons);
  evaluatePrivacyBoundary(input, reasons);
  evaluateExportConsent(input, reasons);
  evaluateVisibilityGrant(input, studyState, reasons);
}

function registryDigest(input) {
  const relevantStudyIds = sortedTextList([input.studyId, input.targetStudyId]);
  const records = studyRegistryRecords(input.studyRegistry).filter((record) => relevantStudyIds.includes(record.studyId));
  return sha256Hex({
    records,
    schema: 'cybermedica.study_registry_scope_evidence.v1',
  });
}

function accessMaterial(input) {
  return {
    actorDid: input.actor.did,
    operation: input.operation,
    protocolRef: input.protocolRef,
    recipientTenantId: input.recipientTenantId ?? null,
    registryDigest: registryDigest(input),
    requestId: input.requestId,
    requestedAtHlc: input.requestedAtHlc,
    resourceArtifactHash: input.resource.artifactHash,
    resourceId: input.resource.resourceId,
    resourceStudyId: input.resource.studyId,
    resourceType: input.resource.resourceType,
    siteId: input.siteId,
    studyId: input.studyId,
    targetStudyId: input.targetStudyId,
    tenantId: input.tenantId,
    visibilityGrantHash: input.visibilityGrant?.grantHash ?? null,
  };
}

function buildReceipt(input, materialHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'study_scope_isolation',
    artifactVersion: `${input.requestId}@${input.operation}`,
    artifactHash: materialHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.requestedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['study_scoped_access', 'metadata_only', 'study_scope_isolation'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildStudyAccess(input, accessId, materialHash, receipt) {
  return {
    accessId,
    actorDid: input.actor.did,
    immutableAccessReceipt: true,
    metadataOnly: true,
    operation: input.operation,
    operationalStateMutable: true,
    protocolRef: input.protocolRef,
    receiptId: receipt.receiptId,
    recipientTenantId: input.recipientTenantId ?? null,
    requestedAtHlc: input.requestedAtHlc,
    resourceHash: materialHash,
    resourceId: input.resource.resourceId,
    resourceType: input.resource.resourceType,
    schema: ACCESS_SCHEMA,
    siteId: input.siteId,
    studyId: input.studyId,
    targetStudyId: input.targetStudyId,
    tenantId: input.tenantId,
  };
}

export function evaluateStudyScopeIsolation(input) {
  const reasons = [];
  validateInput(input, reasons);
  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      studyAccess: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const materialHash = sha256Hex(accessMaterial(input));
  const accessId = `cmsi_${sha256Hex({
    materialHash,
    requestId: input.requestId,
    studyId: input.studyId,
  }).slice(0, 32)}`;
  const receipt = buildReceipt(input, materialHash);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    studyAccess: buildStudyAccess(input, accessId, materialHash, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
