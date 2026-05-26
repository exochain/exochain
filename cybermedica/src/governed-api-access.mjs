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
const API_ACCESS_SCHEMA = 'cybermedica.governed_api_access.v1';

const ACTOR_KINDS = new Set(['human', 'service_account']);
const API_FAMILIES = new Set(['integration', 'reporting']);
const API_METHODS = new Set(['DELETE', 'GET', 'PATCH', 'POST', 'PUT']);
const MUTATING_METHODS = new Set(['DELETE', 'PATCH', 'POST', 'PUT']);

const RAW_API_FIELDS = new Set([
  'body',
  'debugbody',
  'debugpayload',
  'healthdebug',
  'payload',
  'querytext',
  'rawapiresponse',
  'rawbody',
  'rawpayload',
  'rawquery',
  'rawrequest',
  'rawresponse',
  'requestbody',
  'requestpayload',
  'responsebody',
  'responsepayload',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_API_FIELDS = new Set([
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

function assertNoRawApiContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawApiContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_API_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw API payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_API_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`API secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawApiContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawApiContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function includesAll(values, allowed) {
  const allowedSet = new Set(allowed);
  return values.every((value) => allowedSet.has(value));
}

function intersects(left, right) {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
}

function isMutation(method) {
  return MUTATING_METHODS.has(method);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'api_actor_kind_invalid');
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
    !hasAuthorityPermission(input?.authority, 'api_access') && !hasAuthorityPermission(input?.authority, 'govern'),
    'api_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateApiContract(input, reasons) {
  const contract = input?.apiContract;
  addReason(reasons, !hasText(contract?.contractRef), 'api_contract_ref_absent');
  addReason(reasons, !hasText(contract?.contractVersion), 'api_contract_version_absent');
  addReason(reasons, contract?.status !== 'active', 'api_contract_not_active');
  addReason(reasons, !hasText(contract?.approvedByDid), 'api_contract_approver_absent');
  addReason(reasons, hlcTuple(contract?.approvedAtHlc) === null, 'api_contract_approval_time_invalid');
  addReason(reasons, contract?.schemaVersion !== 'cybermedica.governed_api.v1', 'api_contract_schema_invalid');
  addReason(reasons, !isDigest(contract?.openApiSpecHash), 'api_contract_openapi_hash_invalid');
  addReason(reasons, !isDigest(contract?.endpointPolicyHash), 'api_contract_endpoint_policy_hash_invalid');
  addReason(reasons, !isDigest(contract?.authorizationPolicyHash), 'api_contract_authorization_policy_hash_invalid');
  addReason(reasons, !isDigest(contract?.rateLimitPolicyHash), 'api_contract_rate_limit_policy_hash_invalid');
  addReason(reasons, !isDigest(contract?.retentionPolicyHash), 'api_contract_retention_policy_hash_invalid');
  addReason(reasons, contract?.metadataOnly !== true, 'api_contract_metadata_boundary_invalid');
  addReason(reasons, contract?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcAfter(contract?.approvedAtHlc, input?.request?.requestedAtHlc), 'api_contract_after_request');
}

function evaluateIntegrationReadiness(readiness, reasons) {
  addReason(reasons, !hasText(readiness?.readinessRef), 'integration_readiness_ref_absent');
  addReason(reasons, readiness?.readinessStatus !== 'ready', 'integration_readiness_not_ready');
  addReason(reasons, !isDigest(readiness?.readinessHash), 'integration_readiness_hash_invalid');
  addReason(reasons, readiness?.governedApiOnly !== true, 'integration_governed_api_only_absent');
  addReason(reasons, sortedTextList(readiness?.connectorRefs).length === 0, 'integration_connector_refs_absent');
}

function evaluateEndpoint(input, reasons) {
  const endpoint = input?.endpoint;
  const request = input?.request;
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const allowedRoles = sortedTextList(endpoint?.allowedRoleRefs);
  const allowedPurposes = sortedTextList(endpoint?.allowedPurposes);
  const allowedSensitivityTags = sortedTextList(endpoint?.allowedSensitivityTags);
  const requiredScopes = sortedTextList(endpoint?.requiredScopes);

  addReason(reasons, !hasText(endpoint?.endpointRef), 'endpoint_ref_absent');
  addReason(reasons, endpoint?.endpointRef !== request?.endpointRef, 'endpoint_ref_mismatch');
  addReason(reasons, !API_FAMILIES.has(endpoint?.family), `endpoint_family_unsupported:${endpoint?.family ?? 'unknown'}`);
  addReason(reasons, !API_METHODS.has(endpoint?.method), 'endpoint_method_unsupported');
  addReason(reasons, endpoint?.method !== request?.method, 'endpoint_method_mismatch');
  addReason(reasons, !isDigest(endpoint?.routeHash), 'endpoint_route_hash_invalid');
  addReason(reasons, allowedPurposes.length === 0, 'endpoint_allowed_purposes_absent');
  addReason(reasons, hasText(request?.purpose) && !allowedPurposes.includes(request.purpose), 'endpoint_purpose_not_allowed');
  addReason(reasons, requiredScopes.length === 0, 'endpoint_required_scopes_absent');
  addReason(reasons, allowedRoles.length === 0, 'endpoint_allowed_roles_absent');
  addReason(reasons, actorRoles.length === 0 || !intersects(actorRoles, allowedRoles), 'endpoint_role_not_allowed');
  addReason(reasons, allowedSensitivityTags.length === 0, 'endpoint_sensitivity_tags_absent');
  addReason(reasons, !isDigest(endpoint?.responseProfileHash), 'endpoint_response_profile_hash_invalid');
  addReason(reasons, endpoint?.metadataOnly !== true, 'endpoint_metadata_boundary_invalid');
  addReason(reasons, endpoint?.payloadsExcluded !== true, 'endpoint_payload_boundary_invalid');
  addReason(reasons, endpoint?.rawPayloadLoggingDisabled !== true, 'endpoint_raw_payload_logging_forbidden');
}

function evaluateRequest(input, reasons) {
  const request = input?.request;
  addReason(reasons, !hasText(request?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(request?.endpointRef), 'request_endpoint_ref_absent');
  addReason(reasons, !API_METHODS.has(request?.method), 'request_method_unsupported');
  addReason(reasons, !hasText(request?.purpose), 'request_purpose_absent');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'request_time_invalid');
  addReason(reasons, !isDigest(request?.requestMetadataHash), 'request_metadata_hash_invalid');
  addReason(reasons, !isDigest(request?.queryShapeHash), 'request_query_shape_hash_invalid');
  addReason(reasons, sortedTextList(request?.requestedScopes).length === 0, 'request_scopes_absent');
  addReason(reasons, request?.metadataOnly !== true, 'request_metadata_boundary_invalid');
  addReason(reasons, request?.payloadStoredOutsideReceipt !== true, 'request_payload_storage_boundary_invalid');
}

function evaluateAuthentication(input, reasons) {
  const auth = input?.authentication;
  addReason(reasons, auth?.didSignatureVerified !== true, 'authentication_signature_unverified');
  addReason(reasons, !isDigest(auth?.tokenFingerprintHash), 'authentication_token_fingerprint_hash_invalid');
  addReason(reasons, !isDigest(auth?.sessionHash), 'authentication_session_hash_invalid');
  addReason(reasons, hlcTuple(auth?.authenticatedAtHlc) === null, 'authentication_time_invalid');
  addReason(reasons, auth?.secretMaterialExcluded !== true, 'authentication_secret_material_boundary_invalid');
  addReason(reasons, hlcBefore(input?.request?.requestedAtHlc, auth?.authenticatedAtHlc), 'request_before_authentication');
}

function evaluateAuthorizationGrant(input, reasons) {
  const grant = input?.authorizationGrant;
  const grantScopes = sortedTextList(grant?.scopes);
  const requestScopes = sortedTextList(input?.request?.requestedScopes);
  const requiredScopes = sortedTextList(input?.endpoint?.requiredScopes);

  addReason(reasons, !hasText(grant?.grantRef), 'authorization_grant_ref_absent');
  addReason(reasons, !isDigest(grant?.grantHash), 'authorization_grant_hash_invalid');
  addReason(reasons, grant?.status !== 'active', 'authorization_grant_not_active');
  addReason(reasons, grant?.leastPrivilege !== true, 'authorization_least_privilege_absent');
  addReason(reasons, grantScopes.length === 0, 'authorization_scopes_absent');
  addReason(reasons, hlcTuple(grant?.expiresAtHlc) === null, 'authorization_expiration_time_invalid');
  addReason(reasons, hlcBefore(grant?.expiresAtHlc, input?.request?.requestedAtHlc), 'authorization_grant_expired');

  for (const scope of uniqueSorted([...requestScopes, ...requiredScopes])) {
    addReason(reasons, !grantScopes.includes(scope), `requested_scope_not_granted:${scope}`);
  }

  addReason(reasons, !includesAll(requiredScopes, requestScopes), 'request_missing_endpoint_required_scope');
}

function evaluateRateLimit(input, reasons) {
  const rateLimit = input?.rateLimit;
  addReason(reasons, !hasText(rateLimit?.bucketRef), 'rate_limit_bucket_ref_absent');
  addReason(reasons, !isDigest(rateLimit?.policyHash), 'rate_limit_policy_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(rateLimit?.limitPerWindow) || rateLimit.limitPerWindow <= 0,
    'rate_limit_window_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(rateLimit?.usedInWindow) || rateLimit.usedInWindow < 0,
    'rate_limit_usage_invalid',
  );
  addReason(
    reasons,
    Number.isSafeInteger(rateLimit?.limitPerWindow) &&
      Number.isSafeInteger(rateLimit?.usedInWindow) &&
      rateLimit.usedInWindow >= rateLimit.limitPerWindow,
    'rate_limit_exhausted',
  );
  addReason(reasons, hlcTuple(rateLimit?.resetAtHlc) === null, 'rate_limit_reset_time_invalid');
  addReason(reasons, hlcBefore(rateLimit?.resetAtHlc, input?.request?.requestedAtHlc), 'rate_limit_reset_before_request');
}

function evaluateReplayProtection(input, reasons) {
  const replay = input?.replayProtection;
  const method = input?.request?.method;
  addReason(reasons, !isDigest(replay?.nonceHash), 'replay_nonce_hash_invalid');
  addReason(reasons, replay?.noncePreviouslySeen === true, 'replay_nonce_already_seen');
  addReason(reasons, !isDigest(replay?.requestSignatureHash), 'request_signature_hash_invalid');
  addReason(reasons, hlcTuple(replay?.signedAtHlc) === null, 'request_signature_time_invalid');
  addReason(reasons, hlcBefore(replay?.signedAtHlc, input?.authentication?.authenticatedAtHlc), 'request_signature_before_authentication');
  addReason(reasons, hlcAfter(replay?.signedAtHlc, input?.request?.requestedAtHlc), 'request_signature_after_request');
  addReason(
    reasons,
    (replay?.requiredForMutation === true || isMutation(method)) && !isDigest(replay?.idempotencyKeyHash),
    'idempotency_key_hash_invalid',
  );
}

function evaluatePrivacyBoundary(input, reasons) {
  const boundary = input?.privacyBoundary;
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, boundary?.phiPiiExcludedFromRequest !== true, 'privacy_phi_pii_request_boundary_invalid');
  addReason(reasons, boundary?.phiPiiExcludedFromResponse !== true, 'privacy_phi_pii_response_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.sourcePayloadsRemainExternal !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.disclosureLogRequired !== true, 'privacy_disclosure_log_requirement_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');

  if (input?.endpoint?.participantLinked === true) {
    addReason(
      reasons,
      boundary?.participantConsentRequiredWhenLinked !== true,
      'privacy_participant_consent_boundary_invalid',
    );
    evaluateParticipantConsent(input?.consent, reasons);
  }
}

function evaluateParticipantConsent(consent, reasons) {
  addReason(reasons, consent === null || consent === undefined, 'participant_consent_absent');
  addReason(reasons, consent?.required !== true, 'participant_consent_requirement_absent');
  addReason(reasons, !hasText(consent?.consentRef), 'participant_consent_ref_absent');
  addReason(reasons, !hasText(consent?.bailmentRef), 'participant_bailment_ref_absent');
  addReason(reasons, !isDigest(consent?.consentHash), 'participant_consent_hash_invalid');
  addReason(reasons, consent?.status !== 'active', 'participant_consent_not_active');
  addReason(reasons, consent?.revoked === true || consent?.status === 'revoked', 'participant_consent_revoked');
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !hasText(log?.recipientClass), 'disclosure_log_recipient_class_absent');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_log_purpose_absent');
  addReason(reasons, log?.purpose !== input?.request?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, log?.includesRawContent === true, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.request?.requestedAtHlc), 'disclosure_log_before_request');
}

function evaluateResponsePlan(plan, reasons) {
  addReason(reasons, plan?.responseSchema !== 'cybermedica.api_response_metadata.v1', 'response_schema_invalid');
  addReason(reasons, !isDigest(plan?.resultManifestHash), 'response_result_manifest_hash_invalid');
  addReason(reasons, !isDigest(plan?.auditTrailHash), 'response_audit_trail_hash_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'response_metadata_boundary_invalid');
  addReason(reasons, plan?.sourcePayloadExcluded !== true, 'response_source_payload_boundary_invalid');
  addReason(reasons, plan?.healthDebugExcluded !== true, 'response_health_debug_boundary_invalid');
}

function buildApiAccess(input, reasons) {
  const requestScopes = sortedTextList(input?.request?.requestedScopes);
  const requiredScopes = sortedTextList(input?.endpoint?.requiredScopes);
  const scopes = uniqueSorted([...requestScopes, ...requiredScopes]);
  const status = reasons.length === 0 ? 'authorized' : 'blocked';
  const material = {
    actorDid: hasText(input?.actor?.did) ? input.actor.did : null,
    apiContractRef: hasText(input?.apiContract?.contractRef) ? input.apiContract.contractRef : null,
    apiContractVersion: hasText(input?.apiContract?.contractVersion) ? input.apiContract.contractVersion : null,
    disclosureLogHash: hasText(input?.disclosureLog?.disclosureLogHash) ? input.disclosureLog.disclosureLogHash : null,
    endpointRef: hasText(input?.endpoint?.endpointRef) ? input.endpoint.endpointRef : null,
    family: hasText(input?.endpoint?.family) ? input.endpoint.family : null,
    method: hasText(input?.request?.method) ? input.request.method : null,
    purpose: hasText(input?.request?.purpose) ? input.request.purpose : null,
    queryShapeHash: hasText(input?.request?.queryShapeHash) ? input.request.queryShapeHash : null,
    requestId: hasText(input?.request?.requestId) ? input.request.requestId : null,
    requestMetadataHash: hasText(input?.request?.requestMetadataHash) ? input.request.requestMetadataHash : null,
    requestedAtHlc: input?.request?.requestedAtHlc ?? null,
    scopes,
    status,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
  };

  const accessHash = sha256Hex(material);

  return {
    schema: 'cybermedica.governed_api_access_record.v1',
    accessId: `cmapi_${accessHash.slice(0, 32)}`,
    accessHash,
    status,
    tenantId: material.tenantId,
    actorDid: material.actorDid,
    endpointRef: material.endpointRef,
    family: material.family,
    method: material.method,
    purpose: material.purpose,
    scopes,
    participantLinked: input?.endpoint?.participantLinked === true,
    integrationReadinessRef: hasText(input?.integrationReadiness?.readinessRef) ? input.integrationReadiness.readinessRef : null,
    disclosureLogRef: hasText(input?.disclosureLog?.logRef) ? input.disclosureLog.logRef : null,
    responseSchema: hasText(input?.responsePlan?.responseSchema) ? input.responsePlan.responseSchema : null,
    metadataOnly: input?.apiContract?.metadataOnly === true && input?.request?.metadataOnly === true,
    sourcePayloadsStayExternal: input?.privacyBoundary?.sourcePayloadsRemainExternal === true,
    failClosedApiAccess: status !== 'authorized',
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, apiAccess) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: apiAccess.accessHash,
    artifactType: 'governed_api_access',
    artifactVersion: `${input.apiContract.contractRef}@${input.apiContract.contractVersion}:${input.request.requestId}`,
    classification: 'api_access_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.request.requestedAtHlc,
    sensitivityTags: [
      'api_access',
      'integration_metadata',
      'metadata_only',
      'qms_metadata',
      'sponsor_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.governed_api_access',
    tenantId: input.tenantId,
  });
}

export function evaluateGovernedApiAccess(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateApiContract(input, reasons);
  evaluateIntegrationReadiness(input?.integrationReadiness, reasons);
  evaluateEndpoint(input, reasons);
  evaluateRequest(input, reasons);
  evaluateAuthentication(input, reasons);
  evaluateAuthorizationGrant(input, reasons);
  evaluateRateLimit(input, reasons);
  evaluateReplayProtection(input, reasons);
  evaluatePrivacyBoundary(input, reasons);
  evaluateDisclosureLog(input, reasons);
  evaluateResponsePlan(input?.responsePlan, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const apiAccess = buildApiAccess(input, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: API_ACCESS_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      apiAccess,
      receipt: null,
    };
  }

  return {
    schema: API_ACCESS_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    apiAccess,
    receipt: buildReceipt(input, apiAccess),
  };
}
