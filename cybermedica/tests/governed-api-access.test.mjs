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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';

async function loadGovernedApiAccess() {
  try {
    return await import('../src/governed-api-access.mjs');
  } catch (error) {
    assert.fail(`CyberMedica governed API access module must exist and load: ${error.message}`);
  }
}

function apiAccessInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:api-consumer-alpha',
      kind: 'service_account',
      humanOwnerDid: 'did:exo:quality-manager-alpha',
      roleRefs: ['quality_manager', 'sponsor_viewer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['api_access', 'read'],
      authorityChainHash: DIGEST_A,
    },
    apiContract: {
      contractRef: 'api-contract-fr049-alpha',
      contractVersion: 'v1',
      status: 'active',
      approvedByDid: 'did:exo:api-governance-owner',
      approvedAtHlc: { physicalMs: 1796000000000, logical: 1 },
      schemaVersion: 'cybermedica.governed_api.v1',
      openApiSpecHash: DIGEST_B,
      endpointPolicyHash: DIGEST_C,
      authorizationPolicyHash: DIGEST_D,
      rateLimitPolicyHash: DIGEST_E,
      retentionPolicyHash: DIGEST_F,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    integrationReadiness: {
      readinessRef: 'integration-readiness-fr048-alpha',
      readinessStatus: 'ready',
      readinessHash: DIGEST_1,
      governedApiOnly: true,
      connectorRefs: ['connector-ctms-alpha', 'connector-data-warehouse-alpha'],
    },
    endpoint: {
      endpointRef: 'site-readiness-report-api',
      family: 'reporting',
      method: 'GET',
      routeHash: DIGEST_2,
      allowedPurposes: ['integration_sync', 'reporting'],
      requiredScopes: ['api:read', 'report:generate'],
      allowedRoleRefs: ['quality_manager', 'sponsor_viewer'],
      allowedSensitivityTags: ['metadata_only', 'qms_metadata', 'sponsor_confidential_metadata'],
      participantLinked: false,
      responseProfileHash: DIGEST_3,
      metadataOnly: true,
      payloadsExcluded: true,
      rawPayloadLoggingDisabled: true,
    },
    request: {
      requestId: 'api-request-site-readiness-alpha',
      endpointRef: 'site-readiness-report-api',
      method: 'GET',
      purpose: 'reporting',
      requestedAtHlc: { physicalMs: 1796000000000, logical: 20 },
      requestMetadataHash: DIGEST_A,
      queryShapeHash: DIGEST_B,
      requestedScopes: ['report:generate', 'api:read'],
      metadataOnly: true,
      payloadStoredOutsideReceipt: true,
    },
    authentication: {
      didSignatureVerified: true,
      tokenFingerprintHash: DIGEST_C,
      sessionHash: DIGEST_D,
      authenticatedAtHlc: { physicalMs: 1796000000000, logical: 10 },
      secretMaterialExcluded: true,
    },
    authorizationGrant: {
      grantRef: 'api-scope-grant-alpha',
      grantHash: DIGEST_E,
      status: 'active',
      scopes: ['api:read', 'report:generate'],
      leastPrivilege: true,
      expiresAtHlc: { physicalMs: 1796000000001, logical: 0 },
    },
    rateLimit: {
      bucketRef: 'api-reporting-bucket-alpha',
      policyHash: DIGEST_F,
      limitPerWindow: 100,
      usedInWindow: 12,
      resetAtHlc: { physicalMs: 1796000001000, logical: 0 },
    },
    replayProtection: {
      nonceHash: DIGEST_1,
      noncePreviouslySeen: false,
      requestSignatureHash: DIGEST_2,
      signedAtHlc: { physicalMs: 1796000000000, logical: 11 },
      idempotencyKeyHash: DIGEST_3,
      requiredForMutation: true,
    },
    privacyBoundary: {
      boundaryRef: 'api-privacy-boundary-alpha',
      phiPiiExcludedFromRequest: true,
      phiPiiExcludedFromResponse: true,
      sponsorConfidentialMinimized: true,
      sourcePayloadsRemainExternal: true,
      participantConsentRequiredWhenLinked: true,
      disclosureLogRequired: true,
      boundaryHash: DIGEST_A,
    },
    disclosureLog: {
      logRef: 'api-disclosure-log-alpha',
      loggedAtHlc: { physicalMs: 1796000000000, logical: 30 },
      disclosureLogHash: DIGEST_B,
      recipientClass: 'authorized_api_consumer',
      purpose: 'reporting',
      includesRawContent: false,
    },
    responsePlan: {
      responseSchema: 'cybermedica.api_response_metadata.v1',
      resultManifestHash: DIGEST_C,
      auditTrailHash: DIGEST_D,
      metadataOnly: true,
      sourcePayloadExcluded: true,
      healthDebugExcluded: true,
    },
    custodyDigest: DIGEST_E,
    ...overrides,
  };
}

test('governed API access authorizes FR-049 reporting and integration calls with deterministic inactive receipts', async () => {
  const { evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  const resultA = evaluateGovernedApiAccess(apiAccessInput());
  const resultB = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    request: {
      ...apiAccessInput().request,
      requestedScopes: [...apiAccessInput().request.requestedScopes].reverse(),
    },
    endpoint: {
      ...apiAccessInput().endpoint,
      requiredScopes: [...apiAccessInput().endpoint.requiredScopes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.apiAccess.status, 'authorized');
  assert.equal(resultA.apiAccess.endpointRef, 'site-readiness-report-api');
  assert.equal(resultA.apiAccess.family, 'reporting');
  assert.equal(resultA.apiAccess.metadataOnly, true);
  assert.equal(resultA.apiAccess.exochainProductionClaim, false);
  assert.deepEqual(resultA.apiAccess.scopes, ['api:read', 'report:generate']);
  assert.equal(resultA.apiAccess.accessHash, resultB.apiAccess.accessHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'governed_api_access');
  assert.doesNotMatch(JSON.stringify(resultA), /raw body|access token|Participant Alice|source document/iu);
});

test('governed API access fails closed for unsafe authority endpoint contract and rate limits', async () => {
  const { evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  const denied = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    targetTenantId: 'tenant-other',
    actor: {
      did: 'did:exo:api-consumer-alpha',
      kind: 'ai_agent',
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    apiContract: {
      ...apiAccessInput().apiContract,
      status: 'draft',
      metadataOnly: false,
      productionTrustClaim: true,
    },
    endpoint: {
      ...apiAccessInput().endpoint,
      requiredScopes: ['api:read', 'qms:write'],
      rawPayloadLoggingDisabled: false,
    },
    rateLimit: {
      ...apiAccessInput().rateLimit,
      usedInWindow: 100,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.apiAccess.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('api_authority_missing'));
  assert.ok(denied.reasons.includes('api_contract_not_active'));
  assert.ok(denied.reasons.includes('api_contract_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('endpoint_raw_payload_logging_forbidden'));
  assert.ok(denied.reasons.includes('requested_scope_not_granted:qms:write'));
  assert.ok(denied.reasons.includes('rate_limit_exhausted'));
});

test('governed API access requires consent and privacy proof for participant-linked endpoints', async () => {
  const { evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  const denied = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    endpoint: {
      ...apiAccessInput().endpoint,
      participantLinked: true,
      requiredScopes: ['api:read', 'participant:metadata'],
      allowedSensitivityTags: ['metadata_only', 'participant_linked_metadata'],
    },
    request: {
      ...apiAccessInput().request,
      requestedScopes: ['api:read', 'participant:metadata'],
    },
    authorizationGrant: {
      ...apiAccessInput().authorizationGrant,
      scopes: ['api:read', 'participant:metadata'],
    },
    privacyBoundary: {
      ...apiAccessInput().privacyBoundary,
      participantConsentRequiredWhenLinked: false,
      phiPiiExcludedFromResponse: false,
    },
    consent: {
      required: true,
      status: 'revoked',
      revoked: true,
      consentRef: 'consent-participant-alpha',
      bailmentRef: 'bailment-participant-alpha',
      consentHash: DIGEST_F,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('privacy_participant_consent_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_phi_pii_response_boundary_invalid'));
  assert.ok(denied.reasons.includes('participant_consent_revoked'));

  const permitted = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    endpoint: {
      ...apiAccessInput().endpoint,
      participantLinked: true,
      requiredScopes: ['api:read', 'participant:metadata'],
      allowedSensitivityTags: ['metadata_only', 'participant_linked_metadata'],
    },
    request: {
      ...apiAccessInput().request,
      requestedScopes: ['api:read', 'participant:metadata'],
    },
    authorizationGrant: {
      ...apiAccessInput().authorizationGrant,
      scopes: ['api:read', 'participant:metadata'],
    },
    consent: {
      required: true,
      status: 'active',
      revoked: false,
      consentRef: 'consent-participant-alpha',
      bailmentRef: 'bailment-participant-alpha',
      consentHash: DIGEST_F,
    },
  });

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.apiAccess.participantLinked, true);
});

test('governed API access validates replay protection and HLC ordering', async () => {
  const { evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  const mutationAllowed = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    endpoint: {
      ...apiAccessInput().endpoint,
      method: 'POST',
      family: 'integration',
      allowedPurposes: ['integration_sync'],
      requiredScopes: ['api:write', 'integration:sync'],
    },
    request: {
      ...apiAccessInput().request,
      method: 'POST',
      purpose: 'integration_sync',
      requestedScopes: ['integration:sync', 'api:write'],
      requestedAtHlc: { physicalMs: 1796000000000, logical: 11 },
    },
    authorizationGrant: {
      ...apiAccessInput().authorizationGrant,
      scopes: ['api:write', 'integration:sync'],
    },
    authentication: {
      ...apiAccessInput().authentication,
      authenticatedAtHlc: { physicalMs: 1796000000000, logical: 11 },
    },
    replayProtection: {
      ...apiAccessInput().replayProtection,
      signedAtHlc: { physicalMs: 1796000000000, logical: 11 },
    },
    disclosureLog: {
      ...apiAccessInput().disclosureLog,
      purpose: 'integration_sync',
    },
  });

  assert.equal(mutationAllowed.decision, 'permitted');

  const denied = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    authentication: {
      ...apiAccessInput().authentication,
      authenticatedAtHlc: { physicalMs: 1796000000000, logical: 21 },
    },
    replayProtection: {
      ...apiAccessInput().replayProtection,
      noncePreviouslySeen: true,
      signedAtHlc: { physicalMs: 1796000000000, logical: 9 },
      idempotencyKeyHash: null,
    },
    disclosureLog: {
      ...apiAccessInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1796000000000, logical: 19 },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('request_before_authentication'));
  assert.ok(denied.reasons.includes('request_signature_before_authentication'));
  assert.ok(denied.reasons.includes('replay_nonce_already_seen'));
  assert.ok(denied.reasons.includes('idempotency_key_hash_invalid'));
  assert.ok(denied.reasons.includes('disclosure_log_before_request'));

  const malformed = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    request: {
      ...apiAccessInput().request,
      requestedAtHlc: { physicalMs: 1796000000000, logical: -1 },
    },
  });

  assert.ok(malformed.reasons.includes('request_time_invalid'));
});

test('governed API access rejects raw API payloads protected content and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  assert.throws(
    () =>
      evaluateGovernedApiAccess({
        ...apiAccessInput(),
        requestBody: 'raw body with Participant Alice source document',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedApiAccess({
        ...apiAccessInput(),
        authentication: {
          ...apiAccessInput().authentication,
          accessToken: 'must-not-be-stored',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedApiAccess({
        ...apiAccessInput(),
        responsePlan: {
          ...apiAccessInput().responsePlan,
          responseBody: { sourceDocumentText: 'raw source document' },
        },
      }),
    ProtectedContentError,
  );
});

test('governed API access covers inert raw markers and mutation idempotency enforcement', async () => {
  const { ProtectedContentError, evaluateGovernedApiAccess } = await loadGovernedApiAccess();

  const inertRawMarkers = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    rawPayload: [null, false],
    responsePlan: {
      ...apiAccessInput().responsePlan,
      rawResponse: {},
    },
  });

  assert.equal(inertRawMarkers.decision, 'permitted');

  const mutationWithoutIdempotency = evaluateGovernedApiAccess({
    ...apiAccessInput(),
    endpoint: {
      ...apiAccessInput().endpoint,
      method: 'POST',
      family: 'integration',
      allowedPurposes: ['integration_sync'],
      requiredScopes: ['api:write', 'integration:sync'],
    },
    request: {
      ...apiAccessInput().request,
      method: 'POST',
      purpose: 'integration_sync',
      requestedScopes: ['api:write', 'integration:sync'],
    },
    authorizationGrant: {
      ...apiAccessInput().authorizationGrant,
      scopes: ['api:write', 'integration:sync'],
    },
    replayProtection: {
      ...apiAccessInput().replayProtection,
      requiredForMutation: false,
      idempotencyKeyHash: null,
    },
    disclosureLog: {
      ...apiAccessInput().disclosureLog,
      purpose: 'integration_sync',
    },
  });

  assert.equal(mutationWithoutIdempotency.decision, 'denied');
  assert.ok(mutationWithoutIdempotency.reasons.includes('idempotency_key_hash_invalid'));

  assert.throws(
    () =>
      evaluateGovernedApiAccess({
        ...apiAccessInput(),
        rawPayload: 1,
      }),
    ProtectedContentError,
  );
});
