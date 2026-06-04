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
import { TrustState, evaluateGatewayAdjudicationResponse } from './trust-adapter.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const GATEWAY_CALL_SCHEMA = 'cybermedica.gateway_call_path.v1';
const GATEWAY_CALL_DECISION = 'cybermedica.gateway_call_path_decision.v1';
const EXOCHAIN_GATEWAY_SOURCE = 'exochain_gateway';
const EXOCHAIN_DID_REGISTRY_SOURCE = 'exochain_did_registry';
const ROUTE_METHODS = new Set(['DELETE', 'GET', 'PATCH', 'POST', 'PUT']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const ROUTE_STATUSES = new Set(['active']);

const RAW_GATEWAY_FIELDS = new Set([
  'actionpayload',
  'adjudicationpayload',
  'body',
  'debugpayload',
  'gatewaypayload',
  'healthpayload',
  'logpayload',
  'payload',
  'rawbody',
  'rawcontent',
  'rawgatewayrequest',
  'rawgatewayresponse',
  'rawpayload',
  'rawrequest',
  'rawresponse',
  'requestbody',
  'requestpayload',
  'responsebody',
  'responsepayload',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'telemetrypayload',
]);

const SECRET_GATEWAY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'authtoken',
  'bearertoken',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

const SOURCE_EVIDENCE = Object.freeze([
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md#Gateway/API',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-016',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md#RT-001',
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

function assertNoRawGatewayContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawGatewayContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_GATEWAY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw gateway payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_GATEWAY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`gateway secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawGatewayContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawGatewayContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(values) {
  return Array.isArray(values) ? uniqueSorted(values) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hlcTuple(value) {
  if (!Number.isSafeInteger(value?.physicalMs) || !Number.isSafeInteger(value?.logical) || value.logical < 0) {
    return null;
  }
  return [value.physicalMs, value.logical];
}

function compareHlc(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  if (leftTuple === null || rightTuple === null) {
    return null;
  }
  if (leftTuple[0] !== rightTuple[0]) {
    return leftTuple[0] < rightTuple[0] ? -1 : 1;
  }
  if (leftTuple[1] !== rightTuple[1]) {
    return leftTuple[1] < rightTuple[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const result = compareHlc(left, right);
  return result !== null && result < 0;
}

function hlcAfter(left, right) {
  const result = compareHlc(left, right);
  return result !== null && result > 0;
}

function replayBlocks(value, prefix) {
  const blocks = [];
  if (value?.locallySimulated === true || value?.simulated === true) {
    blocks.push(`${prefix}_local_simulation_forbidden`);
  }
  if (value?.cacheHit === true || value?.cachedOutcome === true || value?.cachedReceipt === true) {
    blocks.push(`${prefix}_cached_outcome_forbidden`);
  }
  if (value?.overrideApplied === true || value?.overrideUsed === true) {
    blocks.push(`${prefix}_override_forbidden`);
  }
  return blocks;
}

function evaluateTenantActor(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'gateway_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
}

function evaluateRoute(input, reasons) {
  const route = input?.gatewayRoute;
  const request = input?.gatewayRequest;
  addReason(reasons, !hasText(route?.routeRef), 'gateway_route_ref_absent');
  addReason(reasons, !hasText(route?.endpointRef), 'gateway_endpoint_ref_absent');
  addReason(reasons, route?.endpointRef !== request?.endpointRef, 'gateway_endpoint_ref_mismatch');
  addReason(reasons, !ROUTE_METHODS.has(route?.method), 'gateway_route_method_unsupported');
  addReason(reasons, route?.method !== request?.method, 'gateway_request_method_mismatch');
  addReason(reasons, !hasText(route?.action), 'gateway_route_action_absent');
  addReason(reasons, route?.action !== input?.actionPolicy?.action, 'gateway_route_policy_action_mismatch');
  addReason(reasons, route?.action !== request?.action, 'gateway_route_request_action_mismatch');
  addReason(reasons, !isDigest(route?.routeHash), 'gateway_route_hash_invalid');
  addReason(reasons, route?.enforcementSource !== EXOCHAIN_GATEWAY_SOURCE, 'gateway_route_source_unverified');
  addReason(reasons, !ROUTE_STATUSES.has(route?.status), 'gateway_route_not_active');
  addReason(reasons, route?.runtimeLocation !== 'server_side', 'gateway_route_browser_runtime_forbidden');
  addReason(reasons, route?.failClosedOnUnavailable !== true, 'gateway_route_unavailable_fail_closed_absent');
  addReason(reasons, route?.failClosedOnTimeout !== true, 'gateway_route_timeout_fail_closed_absent');
  addReason(reasons, route?.failClosedOnRejectedDecision !== true, 'gateway_route_rejection_fail_closed_absent');
  addReason(reasons, route?.failClosedOnMalformedResponse !== true, 'gateway_route_malformed_fail_closed_absent');
  addReason(reasons, route?.rawPayloadLoggingDisabled !== true, 'gateway_route_raw_logging_forbidden');
  addReason(reasons, route?.metadataOnly !== true, 'gateway_route_metadata_boundary_invalid');
  addReason(reasons, route?.protectedContentExcluded !== true, 'gateway_route_protected_boundary_invalid');
  addReason(reasons, hlcTuple(route?.approvedAtHlc) === null, 'gateway_route_approval_time_invalid');
  addReason(reasons, hlcAfter(route?.approvedAtHlc, request?.requestedAtHlc), 'gateway_route_approved_after_request');
  reasons.push(...replayBlocks(route, 'gateway_route'));
}

function evaluateActionPolicy(input, reasons) {
  const policy = input?.actionPolicy;
  addReason(reasons, !hasText(policy?.policyRef), 'gateway_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'gateway_policy_hash_invalid');
  addReason(reasons, policy?.sourceRef !== 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md#gateway-call-path', 'gateway_policy_source_ref_invalid');
  addReason(reasons, !hasText(policy?.action), 'gateway_policy_action_absent');
  addReason(reasons, policy?.requiresDidAuthentication !== true, 'gateway_policy_did_auth_absent');
  addReason(reasons, policy?.requiresAuthority !== true, 'gateway_policy_authority_absent');
  addReason(reasons, policy?.requiresInvariantVerdict !== true, 'gateway_policy_invariant_absent');
  addReason(reasons, policy?.forbidsBrowserTrustPath !== true, 'gateway_policy_browser_trust_forbidden_absent');
  addReason(reasons, policy?.forbidsCachedOrSimulatedOutcomes !== true, 'gateway_policy_replay_guard_absent');
  addReason(reasons, policy?.noProductionTrustClaim !== true, 'gateway_policy_trust_claim_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'gateway_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'gateway_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'gateway_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'gateway_policy_after_request');
}

function evaluateRequest(input, reasons) {
  const request = input?.gatewayRequest;
  addReason(reasons, !hasText(request?.requestId), 'gateway_request_id_absent');
  addReason(reasons, !hasText(request?.endpointRef), 'gateway_request_endpoint_ref_absent');
  addReason(reasons, !ROUTE_METHODS.has(request?.method), 'gateway_request_method_unsupported');
  addReason(reasons, !hasText(request?.action), 'gateway_request_action_absent');
  addReason(reasons, !isDigest(request?.actionHash), 'gateway_action_hash_invalid');
  addReason(reasons, !isDigest(request?.requestHash), 'gateway_request_hash_invalid');
  addReason(reasons, !isDigest(request?.idempotencyKeyHash), 'gateway_request_idempotency_hash_invalid');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'gateway_request_time_invalid');
  addReason(reasons, request?.metadataOnly !== true, 'gateway_request_metadata_boundary_invalid');
  addReason(reasons, request?.payloadStoredOutsideReceipt !== true, 'gateway_request_payload_boundary_invalid');
  addReason(reasons, request?.exochainProductionClaim === true, 'gateway_request_production_claim_forbidden');
}

function evaluateDidAuthentication(input, reasons) {
  const did = input?.didAuthentication;
  addReason(reasons, did?.verified !== true || did?.state !== 'verified', 'did_authentication_unverified');
  addReason(reasons, did?.actorDid !== input?.actor?.did, 'did_authentication_actor_mismatch');
  addReason(reasons, did?.registrySource !== EXOCHAIN_DID_REGISTRY_SOURCE, 'did_authentication_registry_source_unverified');
  addReason(reasons, !isDigest(did?.challengeHash), 'did_authentication_challenge_hash_invalid');
  addReason(reasons, !isDigest(did?.signatureHash), 'did_authentication_signature_hash_invalid');
  addReason(reasons, did?.gatewayAuthRequired !== true, 'did_authentication_gateway_requirement_absent');
  addReason(reasons, did?.metadataOnly !== true, 'did_authentication_metadata_boundary_invalid');
  addReason(reasons, did?.protectedContentExcluded !== true, 'did_authentication_protected_boundary_invalid');
  addReason(reasons, hlcTuple(did?.checkedAtHlc) === null, 'did_authentication_time_invalid');
  addReason(reasons, hlcAfter(did?.checkedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'did_authentication_after_request');
  reasons.push(...replayBlocks(did, 'did_authentication'));
}

function evaluateConsentMiddleware(input, reasons) {
  if (input?.actionPolicy?.requiresConsent !== true) {
    return;
  }
  const consent = input?.middleware?.consent;
  addReason(reasons, consent?.required !== true, 'consent_middleware_required_flag_absent');
  addReason(reasons, consent?.verified !== true || consent?.status !== 'active', 'consent_middleware_unverified');
  addReason(reasons, !hasText(consent?.consentRef), 'consent_middleware_ref_absent');
  addReason(reasons, !isDigest(consent?.consentHash), 'consent_middleware_hash_invalid');
  addReason(reasons, consent?.metadataOnly !== true, 'consent_middleware_metadata_boundary_invalid');
  addReason(reasons, consent?.protectedContentExcluded !== true, 'consent_middleware_protected_boundary_invalid');
  addReason(reasons, hlcTuple(consent?.checkedAtHlc) === null, 'consent_middleware_time_invalid');
  addReason(reasons, hlcBefore(consent?.checkedAtHlc, input?.didAuthentication?.checkedAtHlc), 'consent_middleware_before_did_authentication');
  addReason(reasons, hlcAfter(consent?.checkedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'consent_middleware_after_request');
  reasons.push(...replayBlocks(consent, 'consent_middleware'));
}

function evaluateAuthorityMiddleware(input, reasons) {
  const authority = input?.middleware?.authority;
  const permissions = sortedTextList(authority?.permissions);
  addReason(reasons, authority?.verified !== true || authority?.status !== 'valid', 'authority_middleware_unverified');
  addReason(reasons, !isDigest(authority?.authorityChainHash), 'authority_middleware_hash_invalid');
  addReason(reasons, !permissions.includes('govern') && !permissions.includes('execute'), 'authority_middleware_permission_missing');
  addReason(reasons, authority?.metadataOnly !== true, 'authority_middleware_metadata_boundary_invalid');
  addReason(reasons, authority?.protectedContentExcluded !== true, 'authority_middleware_protected_boundary_invalid');
  addReason(reasons, hlcTuple(authority?.checkedAtHlc) === null, 'authority_middleware_time_invalid');
  addReason(reasons, hlcBefore(authority?.checkedAtHlc, input?.didAuthentication?.checkedAtHlc), 'authority_middleware_before_did_authentication');
  addReason(reasons, hlcAfter(authority?.checkedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'authority_middleware_after_request');
  reasons.push(...replayBlocks(authority, 'authority_middleware'));
}

function evaluateQuorumMiddleware(input, reasons) {
  if (input?.actionPolicy?.requiresQuorum !== true) {
    return;
  }
  const quorum = input?.middleware?.quorum;
  addReason(reasons, quorum?.required !== true, 'quorum_middleware_required_flag_absent');
  addReason(reasons, quorum?.verified !== true || quorum?.status !== 'met', 'quorum_middleware_unverified');
  addReason(reasons, !isDigest(quorum?.quorumHash), 'quorum_middleware_hash_invalid');
  addReason(reasons, quorum?.metadataOnly !== true, 'quorum_middleware_metadata_boundary_invalid');
  addReason(reasons, quorum?.protectedContentExcluded !== true, 'quorum_middleware_protected_boundary_invalid');
  addReason(reasons, hlcTuple(quorum?.checkedAtHlc) === null, 'quorum_middleware_time_invalid');
  addReason(reasons, hlcBefore(quorum?.checkedAtHlc, input?.didAuthentication?.checkedAtHlc), 'quorum_middleware_before_did_authentication');
  addReason(reasons, hlcAfter(quorum?.checkedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'quorum_middleware_after_request');
  reasons.push(...replayBlocks(quorum, 'quorum_middleware'));
}

function evaluateInvariantMiddleware(input, reasons) {
  const invariants = input?.middleware?.invariants;
  addReason(reasons, invariants?.verified !== true || invariants?.status !== 'passed', 'invariant_middleware_unverified');
  addReason(reasons, !isDigest(invariants?.invariantSetHash), 'invariant_middleware_hash_invalid');
  addReason(reasons, invariants?.metadataOnly !== true, 'invariant_middleware_metadata_boundary_invalid');
  addReason(reasons, invariants?.protectedContentExcluded !== true, 'invariant_middleware_protected_boundary_invalid');
  addReason(reasons, hlcTuple(invariants?.checkedAtHlc) === null, 'invariant_middleware_time_invalid');
  addReason(reasons, hlcBefore(invariants?.checkedAtHlc, input?.didAuthentication?.checkedAtHlc), 'invariant_middleware_before_did_authentication');
  addReason(reasons, hlcAfter(invariants?.checkedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'invariant_middleware_after_request');
  reasons.push(...replayBlocks(invariants, 'invariant_middleware'));
}

function evaluateValidationEvidence(input, reasons) {
  const validation = input?.validationEvidence;
  addReason(reasons, !Array.isArray(validation?.commandRefs) || validation.commandRefs.length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.gatewayAdapterTestsPassed !== true, 'validation_gateway_adapter_tests_missing');
  addReason(reasons, validation?.didAuthenticationTestsPassed !== true, 'validation_did_authentication_tests_missing');
  addReason(reasons, validation?.consentMiddlewareTestsPassed !== true, 'validation_consent_middleware_tests_missing');
  addReason(reasons, validation?.authorityMiddlewareTestsPassed !== true, 'validation_authority_middleware_tests_missing');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_missing');
  addReason(reasons, !isDigest(validation?.validationHash), 'validation_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, validation?.protectedContentExcluded !== true, 'validation_protected_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.validatedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.validatedAtHlc, input?.gatewayRequest?.requestedAtHlc), 'validation_before_request');
}

function middlewareProofs(input) {
  const proofs = ['authority', 'did_authentication', 'invariants'];
  if (input?.actionPolicy?.requiresConsent === true) {
    proofs.push('consent');
  }
  if (input?.actionPolicy?.requiresQuorum === true) {
    proofs.push('quorum');
  }
  return uniqueSorted(proofs);
}

function classifyStatus(gatewayDecision, reasons) {
  if (reasons.length === 0) {
    return 'verified';
  }
  if (gatewayDecision.state === TrustState.DEGRADED || reasons.includes('gateway_service_unavailable') || reasons.includes('gateway_timeout')) {
    return 'degraded';
  }
  return 'blocked';
}

function buildCallPath(input, gatewayDecision) {
  const proofNames = middlewareProofs(input);
  const callPathHash = sha256Hex({
    action: input.gatewayRequest.action,
    actionHash: input.gatewayRequest.actionHash,
    actorDid: input.actor.did,
    didChallengeHash: input.didAuthentication.challengeHash,
    endpointRef: input.gatewayRequest.endpointRef,
    gatewayReceiptId: gatewayDecision.receiptId,
    idempotencyKeyHash: input.gatewayRequest.idempotencyKeyHash,
    middlewareProofs: proofNames,
    requestHash: input.gatewayRequest.requestHash,
    routeHash: input.gatewayRoute.routeHash,
    tenantId: input.tenantId,
    validationHash: input.validationEvidence.validationHash,
  });

  return {
    schema: GATEWAY_CALL_SCHEMA,
    status: 'verified',
    routeRef: input.gatewayRoute.routeRef,
    endpointRef: input.gatewayRequest.endpointRef,
    action: input.gatewayRequest.action,
    actionHash: input.gatewayRequest.actionHash,
    actorDid: input.actor.did,
    tenantId: input.tenantId,
    gatewayReceiptId: gatewayDecision.receiptId,
    didChallengeHash: input.didAuthentication.challengeHash,
    middlewareProofs: proofNames,
    callPathHash,
    metadataOnly: true,
    exochainProductionClaim: false,
    sourceEvidence: SOURCE_EVIDENCE,
  };
}

function deniedGatewayCall(input, gatewayDecision, reasons) {
  const safeInput = input ?? {};
  return {
    schema: GATEWAY_CALL_SCHEMA,
    status: classifyStatus(gatewayDecision, reasons),
    routeRef: hasText(safeInput.gatewayRoute?.routeRef) ? safeInput.gatewayRoute.routeRef : null,
    endpointRef: hasText(safeInput.gatewayRequest?.endpointRef) ? safeInput.gatewayRequest.endpointRef : null,
    action: hasText(safeInput.gatewayRequest?.action) ? safeInput.gatewayRequest.action : null,
    actionHash: hasText(safeInput.gatewayRequest?.actionHash) ? safeInput.gatewayRequest.actionHash : null,
    actorDid: hasText(safeInput.actor?.did) ? safeInput.actor.did : null,
    tenantId: hasText(safeInput.tenantId) ? safeInput.tenantId : null,
    gatewayReceiptId: gatewayDecision.receiptId,
    didChallengeHash: hasText(safeInput.didAuthentication?.challengeHash) ? safeInput.didAuthentication.challengeHash : null,
    middlewareProofs: middlewareProofs(safeInput),
    callPathHash: null,
    metadataOnly: true,
    exochainProductionClaim: false,
    sourceEvidence: SOURCE_EVIDENCE,
  };
}

export function evaluateGatewayCallPath(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActor(input, reasons);
  evaluateRoute(input, reasons);
  evaluateActionPolicy(input, reasons);
  evaluateRequest(input, reasons);
  evaluateDidAuthentication(input, reasons);
  evaluateConsentMiddleware(input, reasons);
  evaluateAuthorityMiddleware(input, reasons);
  evaluateQuorumMiddleware(input, reasons);
  evaluateInvariantMiddleware(input, reasons);
  evaluateValidationEvidence(input, reasons);

  const gatewayDecision = evaluateGatewayAdjudicationResponse(input?.gatewayResponse, {
    expectedAction: input?.gatewayRequest?.action,
    expectedActorDid: input?.actor?.did,
    expectedTenantId: input?.tenantId,
    expectedActionHash: input?.gatewayRequest?.actionHash,
    requiresConsent: input?.actionPolicy?.requiresConsent === true,
    requiresQuorum: input?.actionPolicy?.requiresQuorum === true,
  });
  reasons.push(...gatewayDecision.blockedBy);

  const blockedBy = uniqueReasons(reasons);
  const permitted = blockedBy.length === 0;
  if (!permitted) {
    return {
      schema: GATEWAY_CALL_DECISION,
      decision: 'denied',
      failClosed: true,
      reasons: blockedBy,
      gatewayCall: deniedGatewayCall(input, gatewayDecision, blockedBy),
      receipt: null,
    };
  }

  const gatewayCall = buildCallPath(input, gatewayDecision);
  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: gatewayCall.callPathHash,
    artifactType: 'gateway_call_path',
    artifactVersion: input.gatewayRoute.routeRef,
    classification: 'metadata_only_gateway_call_path',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.gatewayRequest.requestedAtHlc,
    sensitivityTags: ['gateway_call_path', 'metadata_only', 'inactive_trust'],
    sourceSystem: 'cybermedica.gateway_call_path',
    tenantId: input.tenantId,
  });

  return {
    schema: GATEWAY_CALL_DECISION,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    gatewayCall,
    receipt,
  };
}
