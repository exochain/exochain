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
const INTEGRATION_IMPORT_SCHEMA = 'cybermedica.integration_import_controls.v1';
const REQUIRED_PERMISSION = 'integration_import';

const ACTOR_KINDS = new Set(['human', 'service_account']);
const CONNECTOR_TYPES = new Set([
  'ctms',
  'data_warehouse',
  'document_system',
  'econsent',
  'edc',
  'eisf',
  'etmf',
  'hris',
  'identity_provider',
  'irb_system',
  'lms',
  'qms',
  'sponsor_portal',
]);
const CONNECTOR_MODES = new Set(['bidirectional', 'inbound']);
const CONNECTOR_STATUSES = new Set(['verified']);
const HEALTH_STATUSES = new Set(['passing']);
const IMPORT_FORMATS = new Set(['csv', 'fhir_json', 'json', 'ndjson']);
const OBJECT_FAMILIES = new Set([
  'audit_record',
  'consent_metadata',
  'document_metadata',
  'evidence_index',
  'protocol_metadata',
  'qms_metadata',
  'safety_event_metadata',
  'source_data_index',
  'training_metadata',
  'visit_metadata',
]);
const PARTICIPANT_LINKED_FAMILIES = new Set([
  'consent_metadata',
  'safety_event_metadata',
  'source_data_index',
  'visit_metadata',
]);
const REQUIRED_VALIDATION_CHECKS = Object.freeze([
  'authority',
  'consent',
  'hash',
  'idempotency',
  'privacy',
  'schema',
  'tenant',
]);

const RAW_IMPORT_FIELDS = new Set([
  'body',
  'clinicalnotetext',
  'connectorbody',
  'connectorpayload',
  'connectorrawpayload',
  'directidentifierlist',
  'freetext',
  'freetextnote',
  'healthrawresponse',
  'importrawpayload',
  'participantlisting',
  'rawbody',
  'rawclinicalpayload',
  'rawconnectorpayload',
  'rawhealth',
  'rawimport',
  'rawimportpayload',
  'rawpayload',
  'rawrecord',
  'rawresponse',
  'requestbody',
  'responsebody',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'webhookbody',
]);

const SECRET_IMPORT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'connectorsecret',
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

function assertNoRawImportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawImportContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_IMPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw integration import payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_IMPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`integration import secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawImportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawImportContent(input ?? {});
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

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function connectorRef(connector) {
  return hasText(connector?.connectorRef) ? connector.connectorRef : 'unclassified_connector';
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'import_actor_kind_invalid');
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'manage_integrations') &&
      !hasAuthorityPermission(input?.authority, 'govern'),
    'integration_import_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function evaluateImportRequest(request, reasons) {
  const objectFamilies = sortedTextList(request?.objectFamilies);
  addReason(reasons, !hasText(request?.importRef), 'import_ref_absent');
  addReason(reasons, !hasText(request?.connectorRef), 'import_connector_ref_absent');
  addReason(reasons, !CONNECTOR_TYPES.has(request?.connectorType), `import_connector_type_unsupported:${request?.connectorType ?? 'unknown'}`);
  addReason(reasons, !hasText(request?.systemRef), 'import_system_ref_absent');
  addReason(reasons, !hasText(request?.purpose), 'import_purpose_absent');
  addReason(reasons, !IMPORT_FORMATS.has(request?.format), 'import_format_unsupported');
  addReason(reasons, objectFamilies.length === 0, 'import_object_families_absent');
  for (const family of objectFamilies) {
    addReason(reasons, !OBJECT_FAMILIES.has(family), `import_object_family_unsupported:${family}`);
  }
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'import_requested_time_invalid');
  addReason(reasons, hlcTuple(request?.receivedAtHlc) === null, 'import_received_time_invalid');
  addReason(reasons, hlcBefore(request?.receivedAtHlc, request?.requestedAtHlc), 'import_received_before_requested');
  addReason(reasons, request?.metadataOnly !== true, 'import_metadata_boundary_invalid');
  addReason(reasons, request?.payloadStoredExternally !== true, 'import_payload_storage_boundary_invalid');
  addReason(reasons, request?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  return objectFamilies;
}

function evaluateConnectorEvidence(connector, request, reasons) {
  const ref = connectorRef(connector);
  addReason(reasons, !hasText(connector?.connectorRef), 'connector_evidence_ref_absent');
  addReason(
    reasons,
    hasText(connector?.connectorRef) && hasText(request?.connectorRef) && connector.connectorRef !== request.connectorRef,
    'import_connector_ref_mismatch',
  );
  addReason(reasons, !CONNECTOR_TYPES.has(connector?.type), `connector_type_unsupported:${connector?.type ?? 'unknown'}`);
  addReason(
    reasons,
    hasText(connector?.type) && hasText(request?.connectorType) && connector.type !== request.connectorType,
    'import_connector_type_mismatch',
  );
  addReason(reasons, !hasText(connector?.systemRef), `connector_system_ref_absent:${ref}`);
  addReason(
    reasons,
    hasText(connector?.systemRef) && hasText(request?.systemRef) && connector.systemRef !== request.systemRef,
    'import_system_ref_mismatch',
  );
  addReason(reasons, !CONNECTOR_STATUSES.has(connector?.status), `connector_not_verified:${ref}`);
  addReason(reasons, !CONNECTOR_MODES.has(connector?.mode), `connector_mode_not_inbound:${ref}`);
  addReason(reasons, !isDigest(connector?.configurationHash), `connector_configuration_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.mappingHash), `connector_mapping_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.accessPolicyHash), `connector_access_policy_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.importProfileHash), `connector_import_profile_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(connector?.lastVerifiedAtHlc) === null, `connector_last_verified_time_invalid:${ref}`);
  addReason(reasons, connector?.metadataOnly !== true, `connector_metadata_boundary_invalid:${ref}`);
  addReason(reasons, connector?.payloadStoredOutsideReceipt !== true, `connector_payload_storage_boundary_invalid:${ref}`);
  addReason(reasons, connector?.protectedPayloadExcluded !== true, `connector_protected_payload_boundary_invalid:${ref}`);
  addReason(reasons, connector?.secretsManagedExternally !== true, `connector_secret_scope_invalid:${ref}`);
  addReason(reasons, connector?.failClosedOnError !== true, `connector_fail_closed_absent:${ref}`);
  addReason(reasons, HEALTH_STATUSES.has(connector?.healthCheck?.status) !== true, `connector_health_not_passing:${ref}`);
  addReason(reasons, hlcTuple(connector?.healthCheck?.checkedAtHlc) === null, `connector_health_time_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.healthCheck?.statusHash), `connector_health_check_hash_invalid:${ref}`);
  addReason(reasons, connector?.healthCheck?.rawResponseExcluded !== true, `connector_health_raw_response_forbidden:${ref}`);
  addReason(
    reasons,
    hlcBefore(connector?.healthCheck?.checkedAtHlc, connector?.lastVerifiedAtHlc),
    `connector_health_before_verification:${ref}`,
  );
}

function evaluateSchemaMapping(mapping, objectFamilies, connector, reasons) {
  const supportedFamilies = sortedTextList(mapping?.supportedObjectFamilies);
  addReason(reasons, !hasText(mapping?.mappingRef), 'schema_mapping_ref_absent');
  addReason(reasons, !hasText(mapping?.schemaVersion), 'schema_version_absent');
  addReason(reasons, !isDigest(mapping?.profileHash), 'schema_profile_hash_invalid');
  addReason(reasons, !isDigest(mapping?.fieldMapHash), 'schema_field_map_hash_invalid');
  addReason(reasons, !isDigest(mapping?.validationRulesHash), 'schema_validation_rules_hash_invalid');
  addReason(reasons, supportedFamilies.length === 0, 'schema_supported_families_absent');
  for (const family of objectFamilies) {
    addReason(reasons, !supportedFamilies.includes(family), `schema_family_not_supported:${family}`);
  }
  addReason(reasons, mapping?.tenantPartitioningEnforced !== true, 'schema_tenant_partitioning_absent');
  addReason(reasons, mapping?.defaultDenyUnknownFields !== true, 'schema_default_deny_unknown_fields_absent');
  addReason(reasons, mapping?.directIdentifiersRejected !== true, 'schema_direct_identifier_rejection_absent');
  addReason(reasons, mapping?.sourcePayloadExcluded !== true, 'schema_source_payload_boundary_invalid');
  addReason(reasons, hlcTuple(mapping?.validatedAtHlc) === null, 'schema_validated_time_invalid');
  addReason(reasons, hlcBefore(mapping?.validatedAtHlc, connector?.lastVerifiedAtHlc), 'schema_validated_before_connector_verification');
}

function countIsValid(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function evaluateImportBatch(batch, request, reasons) {
  addReason(reasons, !hasText(batch?.batchRef), 'batch_ref_absent');
  addReason(reasons, !hasText(batch?.sourceSystemBatchRef), 'batch_source_ref_absent');
  addReason(reasons, !isDigest(batch?.sourceHash), 'batch_source_hash_invalid');
  addReason(reasons, !isDigest(batch?.manifestHash), 'batch_manifest_hash_invalid');
  addReason(reasons, !countIsValid(batch?.recordCount), 'batch_record_count_invalid');
  addReason(reasons, !countIsValid(batch?.acceptedRecordCount), 'batch_accepted_count_invalid');
  addReason(reasons, !countIsValid(batch?.rejectedRecordCount), 'batch_rejected_count_invalid');
  addReason(reasons, !countIsValid(batch?.duplicateRecordCount), 'batch_duplicate_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(batch?.recordCount) &&
      Number.isSafeInteger(batch?.acceptedRecordCount) &&
      Number.isSafeInteger(batch?.rejectedRecordCount) &&
      batch.acceptedRecordCount + batch.rejectedRecordCount !== batch.recordCount,
    'batch_accepted_rejected_count_mismatch',
  );
  addReason(reasons, !isDigest(batch?.idempotencyKeyHash), 'batch_idempotency_hash_invalid');
  addReason(reasons, !isDigest(batch?.replayProtectionHash), 'batch_replay_protection_hash_invalid');
  addReason(reasons, hlcTuple(batch?.receivedAtHlc) === null, 'batch_received_time_invalid');
  addReason(reasons, hlcTuple(batch?.validatedAtHlc) === null, 'batch_validated_time_invalid');
  addReason(reasons, hlcBefore(batch?.receivedAtHlc, request?.receivedAtHlc), 'batch_received_before_import_received');
  addReason(reasons, hlcBefore(batch?.validatedAtHlc, batch?.receivedAtHlc), 'batch_validated_before_received');
  addReason(reasons, batch?.metadataOnly !== true, 'batch_metadata_boundary_invalid');
  addReason(reasons, batch?.rawPayloadExcluded !== true, 'batch_raw_payload_boundary_invalid');
  addReason(reasons, batch?.directIdentifiersExcluded !== true, 'batch_direct_identifier_boundary_invalid');
}

function evaluateValidationEvidence(validation, batch, reasons) {
  const checks = sortedTextList(validation?.requiredChecks);
  addReason(reasons, validation?.status !== 'passed', 'validation_status_not_passed');
  addReason(reasons, !isDigest(validation?.validationHash), 'validation_hash_invalid');
  addReason(reasons, checks.length === 0, 'validation_required_checks_absent');
  for (const check of REQUIRED_VALIDATION_CHECKS) {
    addReason(reasons, !checks.includes(check), `validation_required_check_missing:${check}`);
  }
  addReason(reasons, !isDigest(validation?.failedRecordManifestHash), 'validation_failed_record_manifest_hash_invalid');
  addReason(reasons, validation?.rejectedRecordsQuarantined !== true, 'validation_rejected_records_not_quarantined');
  addReason(reasons, validation?.acceptedRecordsMetadataOnly !== true, 'validation_accepted_records_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.checkedAtHlc) === null, 'validation_checked_time_invalid');
  addReason(reasons, hlcBefore(validation?.checkedAtHlc, batch?.validatedAtHlc), 'validation_before_batch_validation');
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, boundary?.phiPiiExcludedFromReceipts !== true, 'privacy_phi_pii_receipt_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.sourcePayloadRetainedExternally !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.participantConsentChecked !== true, 'privacy_participant_consent_boundary_invalid');
  addReason(reasons, boundary?.disclosureLogRequired !== true, 'privacy_disclosure_log_requirement_absent');
  addReason(reasons, boundary?.receiptMetadataMinimized !== true, 'privacy_receipt_metadata_minimization_absent');
}

function importHasParticipantLinkedData(objectFamilies, consent) {
  return consent?.participantLinkedDataPresent === true || objectFamilies.some((family) => PARTICIPANT_LINKED_FAMILIES.has(family));
}

function evaluateConsentBoundary(consent, objectFamilies, reasons) {
  if (!importHasParticipantLinkedData(objectFamilies, consent)) {
    return;
  }
  addReason(reasons, consent?.requiredForParticipantLinkedData !== true, 'participant_consent_boundary_absent');
  addReason(reasons, consent?.participantConsentChecked !== true, 'participant_consent_check_absent');
  addReason(reasons, !isDigest(consent?.consentPolicyHash), 'consent_policy_hash_invalid');
  addReason(reasons, sortedTextList(consent?.activeConsentReceiptRefs).length === 0, 'active_consent_receipt_absent');
  addReason(reasons, !isDigest(consent?.revokedConsentCheckHash), 'revoked_consent_check_hash_invalid');
  addReason(reasons, consent?.revokedConsentDetected === true, 'revoked_consent_detected');
  addReason(reasons, consent?.deniesRevokedConsent !== true, 'revoked_consent_denial_absent');
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, log?.purpose !== input?.importRequest?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, log?.includesRawContent === true, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.validationEvidence?.checkedAtHlc), 'disclosure_log_before_import_validation');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, review?.status !== 'approved', 'human_review_not_approved');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'ai_final_authority_not_rejected');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.validationEvidence?.checkedAtHlc), 'human_review_before_validation');
}

function buildImportManifest(input, objectFamilies, reasons) {
  const status = reasons.length === 0 ? 'accepted_metadata_only' : 'blocked';
  const sourcePayloadExternal =
    input?.importRequest?.payloadStoredExternally === true &&
    input?.connectorEvidence?.payloadStoredOutsideReceipt === true &&
    input?.privacyBoundary?.sourcePayloadRetainedExternally === true;
  const receiptMetadataOnly =
    input?.importRequest?.metadataOnly === true &&
    input?.importBatch?.metadataOnly === true &&
    input?.validationEvidence?.acceptedRecordsMetadataOnly === true &&
    input?.privacyBoundary?.receiptMetadataMinimized === true;
  const participantConsentChecked =
    input?.privacyBoundary?.participantConsentChecked === true &&
    (importHasParticipantLinkedData(objectFamilies, input?.consentBoundary)
      ? input?.consentBoundary?.participantConsentChecked === true
      : true);
  const manifestMaterial = {
    acceptedRecordCount: Number.isSafeInteger(input?.importBatch?.acceptedRecordCount) ? input.importBatch.acceptedRecordCount : null,
    batchRef: hasText(input?.importBatch?.batchRef) ? input.importBatch.batchRef : null,
    connectorRef: hasText(input?.importRequest?.connectorRef) ? input.importRequest.connectorRef : null,
    connectorType: hasText(input?.importRequest?.connectorType) ? input.importRequest.connectorType : null,
    duplicateRecordCount: Number.isSafeInteger(input?.importBatch?.duplicateRecordCount) ? input.importBatch.duplicateRecordCount : null,
    importRef: hasText(input?.importRequest?.importRef) ? input.importRequest.importRef : null,
    objectFamilies,
    recordCount: Number.isSafeInteger(input?.importBatch?.recordCount) ? input.importBatch.recordCount : null,
    rejectedRecordCount: Number.isSafeInteger(input?.importBatch?.rejectedRecordCount) ? input.importBatch.rejectedRecordCount : null,
    schemaMappingRef: hasText(input?.schemaMapping?.mappingRef) ? input.schemaMapping.mappingRef : null,
    sourceHash: isDigest(input?.importBatch?.sourceHash) ? input.importBatch.sourceHash : null,
    status,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    validationHash: isDigest(input?.validationEvidence?.validationHash) ? input.validationEvidence.validationHash : null,
  };

  return {
    schema: 'cybermedica.integration_import_control_manifest.v1',
    manifestId: `cmim_${sha256Hex(manifestMaterial).slice(0, 32)}`,
    manifestHash: sha256Hex(manifestMaterial),
    status,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourcePayloadExternal,
    receiptMetadataOnly,
    participantConsentChecked,
    failClosedImport: status !== 'accepted_metadata_only',
    importRef: manifestMaterial.importRef,
    batchRef: manifestMaterial.batchRef,
    connectorRef: manifestMaterial.connectorRef,
    connectorType: manifestMaterial.connectorType,
    systemRef: hasText(input?.importRequest?.systemRef) ? input.importRequest.systemRef : null,
    objectFamilies,
    sourceHash: manifestMaterial.sourceHash,
    recordCount: manifestMaterial.recordCount,
    acceptedRecordCount: manifestMaterial.acceptedRecordCount,
    rejectedRecordCount: manifestMaterial.rejectedRecordCount,
    duplicateRecordCount: manifestMaterial.duplicateRecordCount,
    schemaMappingRef: manifestMaterial.schemaMappingRef,
    validationHash: manifestMaterial.validationHash,
  };
}

function buildImportReceipt(input, manifest) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: manifest.manifestHash,
    artifactType: 'integration_import_control_manifest',
    artifactVersion: `${input.importRequest.importRef}@${input.importBatch.batchRef}`,
    classification: 'clinical_integration_import_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.validationEvidence.checkedAtHlc,
    sensitivityTags: [
      'clinical_integration_metadata',
      'metadata_only',
      'qms_configuration',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.integration_import_controls',
    tenantId: input.tenantId,
  });
}

export function evaluateIntegrationImportControls(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const objectFamilies = evaluateImportRequest(input?.importRequest, reasons);
  evaluateConnectorEvidence(input?.connectorEvidence, input?.importRequest, reasons);
  evaluateSchemaMapping(input?.schemaMapping, objectFamilies, input?.connectorEvidence, reasons);
  evaluateImportBatch(input?.importBatch, input?.importRequest, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.importBatch, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateConsentBoundary(input?.consentBoundary, objectFamilies, reasons);
  evaluateDisclosureLog(input, reasons);
  evaluateHumanReview(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const importManifest = buildImportManifest(input, objectFamilies, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: INTEGRATION_IMPORT_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      importManifest,
      receipt: null,
    };
  }

  const receipt = buildImportReceipt(input, importManifest);

  return {
    schema: INTEGRATION_IMPORT_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    importManifest,
    receipt,
  };
}
