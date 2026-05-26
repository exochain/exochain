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
const INTEROPERABILITY_SCHEMA = 'cybermedica.interoperability_readiness.v1';
const REQUIRED_PERMISSION = 'interoperability_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_CAPABILITY_FAMILIES = Object.freeze(['api', 'connector', 'import_export_format', 'webhook']);
const REQUIRED_CONNECTOR_TYPES = Object.freeze([
  'ctms',
  'data_warehouse',
  'document_system',
  'econsent',
  'edc',
  'etmf',
  'hris',
  'identity_provider',
  'irb_system',
  'lms',
  'qms',
  'sponsor_portal',
]);
const REQUIRED_EXPORT_FORMATS = Object.freeze(['csv', 'json', 'markdown']);
const REQUIRED_WEBHOOK_EVENTS = Object.freeze([
  'audit_event_recorded',
  'capa_status_changed',
  'consent_status_changed',
  'decision_forum_outcome',
  'evidence_classified',
  'site_readiness_changed',
]);

const ACTOR_KINDS = new Set(['human', 'service_account']);
const CAPABILITY_FAMILIES = new Set(REQUIRED_CAPABILITY_FAMILIES);
const CONNECTOR_TYPES = new Set(REQUIRED_CONNECTOR_TYPES);
const EXPORT_FORMATS = new Set(REQUIRED_EXPORT_FORMATS);
const WEBHOOK_EVENTS = new Set(REQUIRED_WEBHOOK_EVENTS);
const POLICY_STATUSES = new Set(['active']);
const EVIDENCE_STATUSES = new Set(['verified']);
const READY_STATUSES = new Set(['ready']);
const HUMAN_REVIEW_DECISIONS = new Set(['interoperability_ready_inactive_trust']);

const RAW_INTEROPERABILITY_FIELDS = new Set([
  'body',
  'connectorrawpayload',
  'content',
  'debugpayload',
  'exportbody',
  'exportpayload',
  'formatbody',
  'freetext',
  'healthrawresponse',
  'importbody',
  'importpayload',
  'integrationpayload',
  'rawbody',
  'rawconnectorpayload',
  'rawexport',
  'rawformatpayload',
  'rawhealth',
  'rawimport',
  'rawpayload',
  'rawrequest',
  'rawresponse',
  'requestbody',
  'responsebody',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'webhookbody',
  'webhookpayload',
]);

const SECRET_INTEROPERABILITY_FIELDS = new Set([
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

function assertNoRawInteroperabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInteroperabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INTEROPERABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw interoperability payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INTEROPERABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`interoperability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawInteroperabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInteroperabilityContent(input ?? {});
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function listFromPolicy(policy, fieldName, defaults) {
  const values = sortedTextList(policy?.[fieldName]);
  return values.length > 0 ? values : [...defaults];
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, allowedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !allowedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'interoperability_actor_kind_invalid');
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
    'interoperability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'interoperability_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'interoperability_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'interoperability_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'interoperability_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'interoperability_policy_protected_content_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'interoperability_policy_time_invalid');

  const capabilityFamilies = sortedTextList(policy?.requiredCapabilityFamilies);
  const connectorTypes = sortedTextList(policy?.requiredConnectorTypes);
  const exportFormats = sortedTextList(policy?.requiredExportFormats);
  const webhookEvents = sortedTextList(policy?.requiredWebhookEvents);

  evaluateRequiredSet(
    capabilityFamilies,
    REQUIRED_CAPABILITY_FAMILIES,
    'policy_required_capability_family_missing',
    'policy_required_capability_family_unsupported',
    CAPABILITY_FAMILIES,
    reasons,
  );
  evaluateRequiredSet(
    connectorTypes,
    REQUIRED_CONNECTOR_TYPES,
    'policy_required_connector_type_missing',
    'policy_required_connector_type_unsupported',
    CONNECTOR_TYPES,
    reasons,
  );
  evaluateRequiredSet(
    exportFormats,
    REQUIRED_EXPORT_FORMATS,
    'policy_required_export_format_missing',
    'policy_required_export_format_unsupported',
    EXPORT_FORMATS,
    reasons,
  );
  evaluateRequiredSet(
    webhookEvents,
    REQUIRED_WEBHOOK_EVENTS,
    'policy_required_webhook_event_missing',
    'policy_required_webhook_event_unsupported',
    WEBHOOK_EVENTS,
    reasons,
  );
}

function capabilityIdentity(capability) {
  return hasText(capability?.capabilityRef) ? capability.capabilityRef : 'unclassified_capability';
}

function evaluateCapabilityEvidence(input, policy, reasons) {
  const list = Array.isArray(input?.capabilityEvidence) ? input.capabilityEvidence : [];
  addReason(reasons, list.length === 0, 'capability_evidence_absent');
  const families = sortedTextList(list.map((item) => item?.family));
  const requiredFamilies = listFromPolicy(policy, 'requiredCapabilityFamilies', REQUIRED_CAPABILITY_FAMILIES);

  for (const family of requiredFamilies) {
    addReason(reasons, !families.includes(family), `capability_family_missing:${family}`);
  }

  const refs = new Set();
  for (const item of list) {
    const ref = capabilityIdentity(item);
    addReason(reasons, refs.has(ref), `capability_ref_duplicate:${ref}`);
    refs.add(ref);
    addReason(reasons, !hasText(item?.capabilityRef), 'capability_ref_absent');
    addReason(reasons, !CAPABILITY_FAMILIES.has(item?.family), `capability_family_unsupported:${item?.family ?? 'unknown'}`);
    addReason(reasons, !EVIDENCE_STATUSES.has(item?.status), `capability_not_verified:${ref}`);
    addReason(reasons, !isDigest(item?.policyHash), `capability_policy_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(item?.schemaHash), `capability_schema_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(item?.boundaryHash), `capability_boundary_hash_invalid:${ref}`);
    addReason(reasons, hlcTuple(item?.testedAtHlc) === null, `capability_test_time_invalid:${ref}`);
    addReason(reasons, hlcBefore(item?.testedAtHlc, policy?.evaluatedAtHlc), `capability_test_before_policy:${ref}`);
    addReason(reasons, item?.metadataOnly !== true, `capability_metadata_boundary_invalid:${ref}`);
    addReason(reasons, item?.payloadsExcluded !== true, `capability_payload_boundary_invalid:${ref}`);
    addReason(reasons, item?.failClosedOnUnavailable !== true, `capability_fail_closed_absent:${ref}`);
    addReason(reasons, item?.productionTrustClaim === true, `capability_production_trust_claim_forbidden:${ref}`);
  }

  return families;
}

function evaluateGovernedIntegrationReadiness(input, reasons) {
  const readiness = input?.governedIntegrationReadiness;
  addReason(reasons, !hasText(readiness?.readinessRef), 'governed_integration_ref_absent');
  addReason(reasons, !READY_STATUSES.has(readiness?.readinessStatus), 'governed_integration_not_ready');
  addReason(reasons, !isDigest(readiness?.readinessHash), 'governed_integration_hash_invalid');
  addReason(reasons, sortedTextList(readiness?.connectorRefs).length === 0, 'governed_integration_connector_refs_absent');
  addReason(reasons, readiness?.governedApiOnly !== true, 'integration_governed_api_only_absent');
  addReason(reasons, readiness?.metadataOnly !== true, 'governed_integration_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(readiness?.reviewedAtHlc) === null, 'governed_integration_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(readiness?.reviewedAtHlc, input?.interoperabilityPolicy?.evaluatedAtHlc),
    'governed_integration_review_before_policy',
  );
}

function evaluateGovernedApiAccess(input, reasons) {
  const access = input?.governedApiAccess;
  const families = sortedTextList(access?.endpointFamilies);
  addReason(reasons, !hasText(access?.accessRef), 'governed_api_access_ref_absent');
  addReason(reasons, !READY_STATUSES.has(access?.accessStatus), 'governed_api_access_not_ready');
  addReason(reasons, !isDigest(access?.accessHash), 'governed_api_access_hash_invalid');
  addReason(reasons, !families.includes('integration'), 'api_endpoint_family_missing:integration');
  addReason(reasons, !families.includes('reporting'), 'api_endpoint_family_missing:reporting');
  addReason(reasons, !isDigest(access?.openApiSpecHash), 'api_openapi_spec_hash_invalid');
  addReason(reasons, !isDigest(access?.rateLimitPolicyHash), 'api_rate_limit_policy_hash_invalid');
  addReason(reasons, access?.replayProtectionEnabled !== true, 'api_replay_protection_absent');
  addReason(reasons, access?.metadataOnly !== true, 'governed_api_access_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(access?.reviewedAtHlc) === null, 'governed_api_access_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(access?.reviewedAtHlc, input?.interoperabilityPolicy?.evaluatedAtHlc),
    'governed_api_access_review_before_policy',
  );
}

function evaluateStructuredPortability(input, reasons) {
  const portability = input?.structuredDataPortability;
  const exportFamilies = sortedTextList(portability?.exportFamilies);
  addReason(reasons, !hasText(portability?.exportRef), 'structured_portability_ref_absent');
  addReason(reasons, !READY_STATUSES.has(portability?.portabilityStatus), 'structured_portability_not_ready');
  addReason(reasons, !isDigest(portability?.portabilityHash), 'structured_portability_hash_invalid');
  for (const family of ['audit_record', 'diligence_packet', 'evidence_index', 'site_data']) {
    addReason(reasons, !exportFamilies.includes(family), `structured_portability_family_missing:${family}`);
  }
  addReason(reasons, portability?.metadataOnly !== true, 'structured_portability_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(portability?.reviewedAtHlc) === null, 'structured_portability_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(portability?.reviewedAtHlc, input?.interoperabilityPolicy?.evaluatedAtHlc),
    'structured_portability_review_before_policy',
  );
}

function connectorIdentity(connector) {
  return hasText(connector?.connectorRef) ? connector.connectorRef : 'unclassified_connector';
}

function evaluateConnectors(input, policy, reasons) {
  const list = Array.isArray(input?.connectors) ? input.connectors : [];
  addReason(reasons, list.length === 0, 'connectors_absent');
  const connectorTypes = sortedTextList(list.map((item) => item?.type));
  const requiredTypes = listFromPolicy(policy, 'requiredConnectorTypes', REQUIRED_CONNECTOR_TYPES);

  for (const type of requiredTypes) {
    addReason(reasons, !connectorTypes.includes(type), `connector_type_missing:${type}`);
  }

  const refs = new Set();
  for (const connector of list) {
    const ref = connectorIdentity(connector);
    addReason(reasons, refs.has(ref), `connector_ref_duplicate:${ref}`);
    refs.add(ref);
    addReason(reasons, !hasText(connector?.connectorRef), 'connector_ref_absent');
    addReason(reasons, !CONNECTOR_TYPES.has(connector?.type), `connector_type_unsupported:${connector?.type ?? 'unknown'}`);
    addReason(reasons, !EVIDENCE_STATUSES.has(connector?.status), `connector_not_verified:${ref}`);
    addReason(reasons, !hasText(connector?.systemRef), `connector_system_ref_absent:${ref}`);
    addReason(reasons, !isDigest(connector?.mappingHash), `connector_mapping_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(connector?.accessPolicyHash), `connector_access_policy_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(connector?.endpointProfileHash), `connector_endpoint_profile_hash_invalid:${ref}`);
    addReason(reasons, hlcTuple(connector?.lastVerifiedAtHlc) === null, `connector_last_verified_time_invalid:${ref}`);
    addReason(reasons, hlcBefore(connector?.lastVerifiedAtHlc, policy?.evaluatedAtHlc), `connector_verified_before_policy:${ref}`);
    addReason(reasons, connector?.metadataOnly !== true, `connector_metadata_boundary_invalid:${ref}`);
    addReason(reasons, connector?.payloadsExcluded !== true, `connector_payload_boundary_invalid:${ref}`);
    addReason(reasons, connector?.failClosedOnError !== true, `connector_fail_closed_absent:${ref}`);
    addReason(reasons, connector?.secretsManagedExternally !== true, `connector_secret_scope_invalid:${ref}`);
  }

  return connectorTypes;
}

function formatIdentity(format) {
  return hasText(format?.profileRef) ? format.profileRef : 'unclassified_format';
}

function evaluateImportExportFormats(input, policy, reasons) {
  const list = Array.isArray(input?.importExportFormats) ? input.importExportFormats : [];
  addReason(reasons, list.length === 0, 'import_export_formats_absent');
  const formats = sortedTextList(list.map((item) => item?.format));
  const requiredFormats = listFromPolicy(policy, 'requiredExportFormats', REQUIRED_EXPORT_FORMATS);

  for (const format of requiredFormats) {
    addReason(reasons, !formats.includes(format), `export_format_missing:${format}`);
  }

  const refs = new Set();
  for (const item of list) {
    const ref = formatIdentity(item);
    const directions = sortedTextList(item?.supportedDirections);
    addReason(reasons, refs.has(ref), `format_profile_ref_duplicate:${ref}`);
    refs.add(ref);
    addReason(reasons, !hasText(item?.profileRef), 'format_profile_ref_absent');
    addReason(reasons, !EXPORT_FORMATS.has(item?.format), `export_format_unsupported:${item?.format ?? 'unknown'}`);
    addReason(reasons, !isDigest(item?.profileHash), `format_profile_hash_invalid:${ref}`);
    addReason(reasons, item?.schemaVersion !== 'cybermedica.interoperability.format.v1', `format_schema_version_invalid:${ref}`);
    addReason(reasons, !isDigest(item?.validationHash), `format_validation_hash_invalid:${ref}`);
    addReason(reasons, !directions.includes('import'), `format_import_direction_missing:${ref}`);
    addReason(reasons, !directions.includes('export'), `format_export_direction_missing:${ref}`);
    addReason(reasons, item?.metadataOnly !== true, `format_metadata_boundary_invalid:${ref}`);
    addReason(reasons, item?.rawPayloadExcluded !== true, `format_raw_payload_boundary_invalid:${ref}`);
  }

  return formats;
}

function webhookIdentity(webhook) {
  return hasText(webhook?.webhookRef) ? webhook.webhookRef : 'unclassified_webhook';
}

function evaluateWebhookEvents(input, policy, reasons) {
  const list = Array.isArray(input?.webhookEvents) ? input.webhookEvents : [];
  addReason(reasons, list.length === 0, 'webhook_events_absent');
  const events = sortedTextList(list.map((item) => item?.eventType));
  const requiredEvents = listFromPolicy(policy, 'requiredWebhookEvents', REQUIRED_WEBHOOK_EVENTS);

  for (const eventType of requiredEvents) {
    addReason(reasons, !events.includes(eventType), `webhook_event_missing:${eventType}`);
  }

  const refs = new Set();
  for (const webhook of list) {
    const ref = webhookIdentity(webhook);
    addReason(reasons, refs.has(ref), `webhook_ref_duplicate:${ref}`);
    refs.add(ref);
    addReason(reasons, !hasText(webhook?.webhookRef), 'webhook_ref_absent');
    addReason(reasons, !WEBHOOK_EVENTS.has(webhook?.eventType), `webhook_event_unsupported:${webhook?.eventType ?? 'unknown'}`);
    addReason(reasons, !EVIDENCE_STATUSES.has(webhook?.status), `webhook_not_verified:${ref}`);
    addReason(reasons, !isDigest(webhook?.schemaHash), `webhook_schema_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(webhook?.signaturePolicyHash), `webhook_signature_policy_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(webhook?.retryPolicyHash), `webhook_retry_policy_hash_invalid:${ref}`);
    addReason(reasons, webhook?.signatureRequired !== true, `webhook_signature_absent:${ref}`);
    addReason(reasons, webhook?.replayProtectionEnabled !== true, `webhook_replay_protection_absent:${ref}`);
    addReason(reasons, webhook?.idempotencyRequired !== true, `webhook_idempotency_absent:${ref}`);
    addReason(reasons, webhook?.rawPayloadLoggingDisabled !== true, `webhook_raw_payload_logging_forbidden:${ref}`);
    addReason(reasons, hlcTuple(webhook?.lastVerifiedAtHlc) === null, `webhook_last_verified_time_invalid:${ref}`);
    addReason(reasons, hlcBefore(webhook?.lastVerifiedAtHlc, policy?.evaluatedAtHlc), `webhook_verified_before_policy:${ref}`);
    addReason(reasons, webhook?.metadataOnly !== true, `webhook_metadata_boundary_invalid:${ref}`);
    addReason(reasons, webhook?.payloadsExcluded !== true, `webhook_payload_boundary_invalid:${ref}`);
  }

  return events;
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, boundary?.phiPiiExcludedFromReceipts !== true, 'privacy_phi_pii_receipt_boundary_invalid');
  addReason(reasons, boundary?.sourcePayloadsRemainExternal !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.disclosureLoggingRequired !== true, 'privacy_disclosure_log_requirement_absent');
  addReason(reasons, boundary?.participantConsentCheckedWhenLinked !== true, 'privacy_participant_consent_boundary_invalid');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'human_review_ai_final_authority_not_rejected');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.interoperabilityPolicy?.evaluatedAtHlc),
    'human_review_before_policy',
  );
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(aiAssistance.scopeHash), 'ai_scope_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
}

function buildInteroperabilityReadiness(input, lists, reasons) {
  const status = reasons.length === 0 ? 'ready' : 'blocked';
  const material = {
    apiAccessRef: hasText(input?.governedApiAccess?.accessRef) ? input.governedApiAccess.accessRef : null,
    capabilityFamilies: lists.capabilityFamilies,
    connectorTypes: lists.connectorTypes,
    exportFormats: lists.exportFormats,
    integrationReadinessRef: hasText(input?.governedIntegrationReadiness?.readinessRef)
      ? input.governedIntegrationReadiness.readinessRef
      : null,
    policyRef: hasText(input?.interoperabilityPolicy?.policyRef) ? input.interoperabilityPolicy.policyRef : null,
    portabilityRef: hasText(input?.structuredDataPortability?.exportRef) ? input.structuredDataPortability.exportRef : null,
    privacyBoundaryRef: hasText(input?.privacyBoundary?.boundaryRef) ? input.privacyBoundary.boundaryRef : null,
    status,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    webhookEvents: lists.webhookEvents,
  };

  return {
    schema: 'cybermedica.interoperability_readiness_snapshot.v1',
    readinessId: `cmi_${sha256Hex(material).slice(0, 32)}`,
    readinessHash: sha256Hex(material),
    status,
    capabilityFamilies: lists.capabilityFamilies,
    connectorTypes: lists.connectorTypes,
    exportFormats: lists.exportFormats,
    webhookEvents: lists.webhookEvents,
    governedIntegrationReady: input?.governedIntegrationReadiness?.readinessStatus === 'ready',
    governedApiAccessReady: input?.governedApiAccess?.accessStatus === 'ready',
    structuredPortabilityReady: input?.structuredDataPortability?.portabilityStatus === 'ready',
    metadataOnly: input?.interoperabilityPolicy?.metadataOnly === true,
    sourcePayloadsStayExternal: input?.privacyBoundary?.sourcePayloadsRemainExternal === true,
    failClosedInteroperability: status !== 'ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReadinessReceipt(input, readiness) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: readiness.readinessHash,
    artifactType: 'interoperability_readiness',
    artifactVersion: `nfr007:${input.interoperabilityPolicy.policyRef}`,
    classification: 'interoperability_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'integration_metadata',
      'interoperability_metadata',
      'metadata_only',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.interoperability_readiness',
    tenantId: input.tenantId,
  });
}

export function evaluateInteroperabilityReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.interoperabilityPolicy, reasons);
  const capabilityFamilies = evaluateCapabilityEvidence(input, input?.interoperabilityPolicy, reasons);
  evaluateGovernedIntegrationReadiness(input, reasons);
  evaluateGovernedApiAccess(input, reasons);
  evaluateStructuredPortability(input, reasons);
  const connectorTypes = evaluateConnectors(input, input?.interoperabilityPolicy, reasons);
  const exportFormats = evaluateImportExportFormats(input, input?.interoperabilityPolicy, reasons);
  const webhookEvents = evaluateWebhookEvents(input, input?.interoperabilityPolicy, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateHumanReview(input, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);

  const denialReasons = uniqueReasons(reasons);
  const interoperabilityReadiness = buildInteroperabilityReadiness(
    input,
    {
      capabilityFamilies,
      connectorTypes,
      exportFormats,
      webhookEvents,
    },
    denialReasons,
  );

  if (denialReasons.length > 0) {
    return {
      schema: INTEROPERABILITY_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: denialReasons,
      denialReasons,
      interoperabilityReadiness,
      receipt: null,
    };
  }

  const receipt = buildReadinessReceipt(input, interoperabilityReadiness);

  return {
    schema: INTEROPERABILITY_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    interoperabilityReadiness,
    receipt,
  };
}
