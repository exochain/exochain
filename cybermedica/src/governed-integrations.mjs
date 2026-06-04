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
const INTEGRATION_SCHEMA = 'cybermedica.governed_integrations.v1';

const REQUIRED_CONNECTOR_TYPES = Object.freeze([
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

const CONNECTOR_TYPES = new Set(REQUIRED_CONNECTOR_TYPES);
const CONNECTOR_MODES = new Set(['bidirectional', 'inbound', 'outbound', 'read_only', 'write_only']);
const CONNECTOR_STATUSES = new Set(['verified']);
const HEALTH_STATUSES = new Set(['passing']);

const RAW_INTEGRATION_FIELDS = new Set([
  'connectorrawpayload',
  'connectorrawresponse',
  'contactemail',
  'datapayload',
  'freeformmapping',
  'healthrawresponse',
  'integrationpayload',
  'rawbody',
  'rawconnectorpayload',
  'rawcontact',
  'rawexport',
  'rawhealth',
  'rawimport',
  'rawmessage',
  'rawpayload',
  'rawresponse',
  'requestbody',
  'responsebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'webhookbody',
]);

const SECRET_INTEGRATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
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
  'signaturesecret',
  'signingkey',
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

function assertNoRawIntegrationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawIntegrationContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INTEGRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw integration payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INTEGRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`integration secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawIntegrationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawIntegrationContent(input ?? {});
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

function connectorIdentity(connector) {
  return hasText(connector?.connectorRef) ? connector.connectorRef : 'unclassified_connector';
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
    !hasAuthorityPermission(input?.authority, 'manage_integrations') && !hasAuthorityPermission(input?.authority, 'govern'),
    'integration_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateIntegrationPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'integration_plan_ref_absent');
  addReason(reasons, !hasText(plan?.planVersion), 'integration_plan_version_absent');
  addReason(reasons, plan?.approved !== true, 'integration_plan_not_approved');
  addReason(reasons, !hasText(plan?.approvedByDid), 'integration_plan_approver_absent');
  addReason(reasons, !isDigest(plan?.scopeHash), 'integration_plan_scope_hash_invalid');
  addReason(reasons, !isDigest(plan?.systemOfRecordPolicyHash), 'system_of_record_policy_hash_invalid');
  addReason(reasons, !isDigest(plan?.dataMinimizationHash), 'data_minimization_hash_invalid');
  addReason(reasons, !isDigest(plan?.accessReviewHash), 'access_review_hash_invalid');
  addReason(reasons, hlcTuple(plan?.testedAtHlc) === null, 'integration_plan_test_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'integration_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateEndpointPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'endpoint_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'endpoint_policy_hash_invalid');
  addReason(reasons, policy?.governedApiOnly !== true, 'endpoint_governed_api_only_absent');
  addReason(reasons, policy?.webhookSignatureRequired !== true, 'endpoint_webhook_signature_absent');
  addReason(reasons, policy?.importExportFormatsApproved !== true, 'endpoint_import_export_formats_unapproved');
  addReason(reasons, policy?.leastPrivilegeScopes !== true, 'endpoint_least_privilege_absent');
  addReason(reasons, policy?.rateLimitConfigured !== true, 'endpoint_rate_limit_absent');
  addReason(reasons, policy?.replayProtectionEnabled !== true, 'endpoint_replay_protection_absent');
  addReason(reasons, policy?.schemaVersioningRequired !== true, 'endpoint_schema_versioning_absent');
  addReason(reasons, policy?.rawPayloadLoggingDisabled !== true, 'endpoint_raw_payload_logging_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'endpoint_policy_time_invalid');
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, boundary?.phiPiiExcludedFromReceipts !== true, 'privacy_phi_pii_receipt_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.payloadsRemainInSourceSystems !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.disclosureLogRequired !== true, 'privacy_disclosure_log_requirement_absent');
  addReason(reasons, boundary?.consentCheckedForParticipantLinkedData !== true, 'privacy_participant_consent_boundary_invalid');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !hasText(log?.recipientClass), 'disclosure_log_recipient_class_absent');
  addReason(reasons, log?.includesRawContent === true, 'disclosure_log_raw_content_forbidden');
  addReason(
    reasons,
    hlcBefore(log?.loggedAtHlc, input?.endpointPolicy?.evaluatedAtHlc),
    'disclosure_log_before_endpoint_policy',
  );
}

function evaluateConnector(connector, reasons) {
  const ref = connectorIdentity(connector);
  addReason(reasons, !hasText(connector?.connectorRef), 'connector_ref_absent');
  addReason(reasons, !CONNECTOR_TYPES.has(connector?.type), `connector_type_unsupported:${connector?.type ?? 'unknown'}`);
  addReason(reasons, !hasText(connector?.systemRef), `connector_system_ref_absent:${ref}`);
  addReason(reasons, !CONNECTOR_STATUSES.has(connector?.status), `connector_not_verified:${ref}`);
  addReason(reasons, !CONNECTOR_MODES.has(connector?.mode), `connector_mode_invalid:${ref}`);
  addReason(reasons, !hasText(connector?.ownerDid), `connector_owner_absent:${ref}`);
  addReason(reasons, !isDigest(connector?.configurationHash), `connector_configuration_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.mappingHash), `connector_mapping_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.accessPolicyHash), `connector_access_policy_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.webhookPolicyHash), `connector_webhook_policy_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.importProfileHash), `connector_import_profile_hash_invalid:${ref}`);
  addReason(reasons, !isDigest(connector?.exportProfileHash), `connector_export_profile_hash_invalid:${ref}`);
  addReason(reasons, hlcTuple(connector?.lastVerifiedAtHlc) === null, `connector_last_verified_time_invalid:${ref}`);
  addReason(reasons, sortedTextList(connector?.dataClasses).length === 0, `connector_data_classes_absent:${ref}`);
  addReason(reasons, connector?.metadataOnly !== true, `connector_metadata_boundary_invalid:${ref}`);
  addReason(reasons, connector?.payloadStoredOutsideReceipt !== true, `connector_payload_storage_boundary_invalid:${ref}`);
  addReason(reasons, connector?.protectedPayloadExcluded !== true, `connector_protected_payload_boundary_invalid:${ref}`);
  addReason(reasons, connector?.secretsManagedExternally !== true, `connector_secret_scope_invalid:${ref}`);
  addReason(reasons, connector?.failClosedOnError !== true, `connector_fail_closed_absent:${ref}`);
  addReason(reasons, connector?.retryPolicy?.idempotencyKeyRequired !== true, `connector_idempotency_absent:${ref}`);
  addReason(reasons, connector?.retryPolicy?.duplicateDeliverySafe !== true, `connector_duplicate_delivery_safety_absent:${ref}`);
  addReason(
    reasons,
    !Number.isSafeInteger(connector?.retryPolicy?.maxRetryCount) || connector.retryPolicy.maxRetryCount <= 0,
    `connector_retry_count_invalid:${ref}`,
  );
  addReason(reasons, hlcTuple(connector?.healthCheck?.checkedAtHlc) === null, `connector_health_time_invalid:${ref}`);
  addReason(reasons, HEALTH_STATUSES.has(connector?.healthCheck?.status) !== true, `connector_health_not_passing:${ref}`);
  addReason(reasons, !isDigest(connector?.healthCheck?.statusHash), `connector_health_check_hash_invalid:${ref}`);
  addReason(reasons, connector?.healthCheck?.rawResponseExcluded !== true, `connector_health_raw_response_forbidden:${ref}`);
  addReason(
    reasons,
    hlcBefore(connector?.healthCheck?.checkedAtHlc, connector?.lastVerifiedAtHlc),
    `connector_health_before_verification:${ref}`,
  );
}

function evaluateConnectors(connectors, reasons) {
  const list = Array.isArray(connectors) ? connectors : [];
  addReason(reasons, list.length === 0, 'connectors_absent');

  const connectorTypes = sortedTextList(list.map((item) => item?.type));
  for (const type of REQUIRED_CONNECTOR_TYPES) {
    addReason(reasons, !connectorTypes.includes(type), `connector_type_missing:${type}`);
  }

  const refs = new Set();
  for (const connector of list) {
    const ref = connectorIdentity(connector);
    addReason(reasons, refs.has(ref), `connector_ref_duplicate:${ref}`);
    refs.add(ref);
    evaluateConnector(connector, reasons);
  }

  return { connectorTypes, list };
}

function connectorSummaries(connectors) {
  return connectors
    .map((connector) => ({
      connectorRef: connectorIdentity(connector),
      dataClasses: sortedTextList(connector?.dataClasses),
      mode: hasText(connector?.mode) ? connector.mode : 'unclassified',
      status: hasText(connector?.status) ? connector.status : 'unverified',
      systemRef: hasText(connector?.systemRef) ? connector.systemRef : 'unclassified',
      type: hasText(connector?.type) ? connector.type : 'unknown',
    }))
    .sort((left, right) => `${left.type}:${left.connectorRef}`.localeCompare(`${right.type}:${right.connectorRef}`));
}

function buildIntegrationReadiness(input, connectorTypes, connectorList, reasons) {
  const missingConnectorTypes = REQUIRED_CONNECTOR_TYPES.filter((type) => !connectorTypes.includes(type));
  const connectorSummary = connectorSummaries(connectorList);
  const status = reasons.length === 0 ? 'ready' : 'blocked';
  const readinessMaterial = {
    connectorSummary,
    endpointPolicyRef: hasText(input?.endpointPolicy?.policyRef) ? input.endpointPolicy.policyRef : null,
    missingConnectorTypes,
    planRef: hasText(input?.integrationPlan?.planRef) ? input.integrationPlan.planRef : null,
    planVersion: hasText(input?.integrationPlan?.planVersion) ? input.integrationPlan.planVersion : null,
    privacyBoundaryRef: hasText(input?.privacyBoundary?.boundaryRef) ? input.privacyBoundary.boundaryRef : null,
    status,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
  };

  return {
    schema: 'cybermedica.governed_integrations_readiness.v1',
    readinessId: `cmgi_${sha256Hex(readinessMaterial).slice(0, 32)}`,
    readinessHash: sha256Hex(readinessMaterial),
    status,
    connectorCount: connectorList.length,
    connectorTypes,
    missingConnectorTypes,
    connectorSummary,
    governedApiOnly: input?.endpointPolicy?.governedApiOnly === true,
    webhookSignatureRequired: input?.endpointPolicy?.webhookSignatureRequired === true,
    importExportFormatsApproved: input?.endpointPolicy?.importExportFormatsApproved === true,
    metadataOnly: input?.integrationPlan?.metadataOnly === true,
    sourcePayloadsStayExternal: input?.privacyBoundary?.payloadsRemainInSourceSystems === true,
    failClosedIntegration: status !== 'ready',
    exochainProductionClaim: false,
  };
}

function buildReadinessReceipt(input, readiness) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: readiness.readinessHash,
    artifactType: 'governed_integrations_readiness',
    artifactVersion: `${input.integrationPlan.planRef}@${input.integrationPlan.planVersion}`,
    classification: 'integration_readiness_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.integrationPlan.testedAtHlc,
    sensitivityTags: [
      'integration_metadata',
      'metadata_only',
      'qms_configuration',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.governed_integrations',
    tenantId: input.tenantId,
  });
}

export function evaluateGovernedIntegrations(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateIntegrationPlan(input?.integrationPlan, reasons);
  evaluateEndpointPolicy(input?.endpointPolicy, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateDisclosureLog(input, reasons);
  const { connectorTypes, list } = evaluateConnectors(input?.connectors, reasons);
  const uniqueReasons = uniqueSorted(reasons);
  const integrationReadiness = buildIntegrationReadiness(input, connectorTypes, list, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: INTEGRATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      integrationReadiness,
      receipt: null,
    };
  }

  const receipt = buildReadinessReceipt(input, integrationReadiness);

  return {
    schema: INTEGRATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    integrationReadiness,
    receipt,
  };
}
