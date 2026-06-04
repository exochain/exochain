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
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const GATEWAY_ENFORCEMENT_ACTIVATION_GATE_ID = 'PTAG-016';

async function loadGatewayCallPath() {
  try {
    return await import('../src/gateway-call-path.mjs');
  } catch (error) {
    assert.fail(`CyberMedica gateway call-path module must exist and load: ${error.message}`);
  }
}

function gatewayCallInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:principal-investigator-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'protocol_launch_reviewer'],
    },
    gatewayRoute: {
      routeRef: 'exochain-gateway-protocol-launch-alpha',
      endpointRef: 'gateway-adjudicate-protocol-launch',
      method: 'POST',
      action: 'protocol_launch',
      routeHash: DIGEST_A,
      enforcementSource: 'exochain_gateway',
      status: 'active',
      runtimeLocation: 'server_side',
      failClosedOnUnavailable: true,
      failClosedOnTimeout: true,
      failClosedOnRejectedDecision: true,
      failClosedOnMalformedResponse: true,
      rawPayloadLoggingDisabled: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      approvedAtHlc: { physicalMs: 1810000000000, logical: 0 },
    },
    actionPolicy: {
      policyRef: 'gateway-action-policy-protocol-launch-alpha',
      policyHash: DIGEST_B,
      sourceRef: 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md#gateway-call-path',
      action: 'protocol_launch',
      requiresDidAuthentication: true,
      requiresConsent: true,
      requiresAuthority: true,
      requiresQuorum: true,
      requiresInvariantVerdict: true,
      forbidsBrowserTrustPath: true,
      forbidsCachedOrSimulatedOutcomes: true,
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1810000000000, logical: 1 },
    },
    gatewayRequest: {
      requestId: 'gateway-request-protocol-launch-alpha',
      endpointRef: 'gateway-adjudicate-protocol-launch',
      method: 'POST',
      action: 'protocol_launch',
      actionHash: DIGEST_C,
      requestHash: DIGEST_D,
      idempotencyKeyHash: DIGEST_E,
      requestedAtHlc: { physicalMs: 1810000000000, logical: 10 },
      metadataOnly: true,
      payloadStoredOutsideReceipt: true,
      exochainProductionClaim: false,
    },
    didAuthentication: {
      verified: true,
      state: 'verified',
      actorDid: 'did:exo:principal-investigator-alpha',
      registrySource: 'exochain_did_registry',
      challengeHash: DIGEST_F,
      signatureHash: DIGEST_1,
      gatewayAuthRequired: true,
      checkedAtHlc: { physicalMs: 1810000000000, logical: 2 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    middleware: {
      consent: {
        required: true,
        verified: true,
        status: 'active',
        consentRef: 'consent-protocol-launch-alpha',
        consentHash: DIGEST_2,
        checkedAtHlc: { physicalMs: 1810000000000, logical: 3 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      authority: {
        verified: true,
        status: 'valid',
        authorityChainHash: DIGEST_3,
        permissions: ['govern', 'execute'],
        checkedAtHlc: { physicalMs: 1810000000000, logical: 4 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      quorum: {
        required: true,
        verified: true,
        status: 'met',
        quorumHash: DIGEST_4,
        checkedAtHlc: { physicalMs: 1810000000000, logical: 5 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      invariants: {
        verified: true,
        status: 'passed',
        invariantSetHash: DIGEST_5,
        checkedAtHlc: { physicalMs: 1810000000000, logical: 6 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
    },
    gatewayResponse: {
      status: 'ok',
      enforcementSource: 'exochain_gateway',
      decision: 'permitted',
      action: 'protocol_launch',
      actorDid: 'did:exo:principal-investigator-alpha',
      tenantId: 'tenant-site-alpha',
      auth: { verified: true, status: 'verified' },
      consent: { verified: true, status: 'active' },
      authority: { verified: true, status: 'valid' },
      quorum: { verified: true, status: 'met' },
      invariants: { verified: true, status: 'passed' },
      provenance: {
        receiptId: 'receipt-gateway-protocol-launch-alpha',
        actionHash: DIGEST_C,
        signature: 'sig-gateway-alpha',
        receiptSource: 'exochain_node_receipt_store',
        anchorPayload: { artifactHash: DIGEST_C, artifactType: 'protocol_launch_gate' },
      },
    },
    validationEvidence: {
      commandRefs: ['node --test tests/gateway-call-path.test.mjs', 'npm run quality'],
      gatewayAdapterTestsPassed: true,
      didAuthenticationTestsPassed: true,
      consentMiddlewareTestsPassed: true,
      authorityMiddlewareTestsPassed: true,
      sourceGuardPassed: true,
      validationHash: DIGEST_A,
      validatedAtHlc: { physicalMs: 1810000000000, logical: 20 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_B,
  };

  return {
    ...base,
    ...overrides,
    actor: { ...base.actor, ...overrides.actor },
    gatewayRoute: { ...base.gatewayRoute, ...overrides.gatewayRoute },
    actionPolicy: { ...base.actionPolicy, ...overrides.actionPolicy },
    gatewayRequest: { ...base.gatewayRequest, ...overrides.gatewayRequest },
    didAuthentication: { ...base.didAuthentication, ...overrides.didAuthentication },
    middleware: {
      consent: { ...base.middleware.consent, ...overrides.middleware?.consent },
      authority: { ...base.middleware.authority, ...overrides.middleware?.authority },
      quorum: { ...base.middleware.quorum, ...overrides.middleware?.quorum },
      invariants: { ...base.middleware.invariants, ...overrides.middleware?.invariants },
    },
    gatewayResponse:
      overrides.gatewayResponse === null ? null : { ...base.gatewayResponse, ...overrides.gatewayResponse },
    validationEvidence: { ...base.validationEvidence, ...overrides.validationEvidence },
  };
}

test('gateway call path creates deterministic inactive evidence for DID-authenticated gateway routing', async () => {
  const { evaluateGatewayCallPath } = await loadGatewayCallPath();

  const first = evaluateGatewayCallPath(gatewayCallInput());
  const second = evaluateGatewayCallPath({
    ...gatewayCallInput(),
    actor: {
      ...gatewayCallInput().actor,
      roleRefs: [...gatewayCallInput().actor.roleRefs].reverse(),
    },
    middleware: {
      ...gatewayCallInput().middleware,
      authority: {
        ...gatewayCallInput().middleware.authority,
        permissions: [...gatewayCallInput().middleware.authority.permissions].reverse(),
      },
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.gatewayCall.status, 'verified');
  assert.equal(first.gatewayCall.gatewayReceiptId, 'receipt-gateway-protocol-launch-alpha');
  assert.equal(first.gatewayCall.didChallengeHash, DIGEST_F);
  assert.deepEqual(first.gatewayCall.middlewareProofs, ['authority', 'consent', 'did_authentication', 'invariants', 'quorum']);
  assert.equal(first.gatewayCall.metadataOnly, true);
  assert.equal(first.gatewayCall.exochainProductionClaim, false);
  assert.ok(
    first.gatewayCall.sourceEvidence.includes(
      `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#${GATEWAY_ENFORCEMENT_ACTIVATION_GATE_ID}`,
    ),
  );
  assert.equal(first.gatewayCall.callPathHash, second.gatewayCall.callPathHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'gateway_call_path');
  assert.doesNotMatch(JSON.stringify(first), /raw payload|access token|source document/iu);
});

test('gateway call path fails closed for unavailable gateway invalid DID and middleware denials', async () => {
  const { evaluateGatewayCallPath } = await loadGatewayCallPath();

  const denied = evaluateGatewayCallPath(
    gatewayCallInput({
      didAuthentication: {
        verified: false,
        state: 'denied',
      },
      middleware: {
        consent: {
          verified: false,
          status: 'revoked',
        },
        authority: {
          verified: false,
          status: 'revoked',
          permissions: ['read'],
        },
        quorum: {
          verified: false,
          status: 'not_met',
        },
      },
      gatewayResponse: null,
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.gatewayCall.status, 'degraded');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('did_authentication_unverified'));
  assert.ok(denied.reasons.includes('consent_middleware_unverified'));
  assert.ok(denied.reasons.includes('authority_middleware_unverified'));
  assert.ok(denied.reasons.includes('quorum_middleware_unverified'));
  assert.ok(denied.reasons.includes('gateway_service_unavailable'));
});

test('gateway call path blocks browser runtime cached outcomes and action mismatches', async () => {
  const { evaluateGatewayCallPath } = await loadGatewayCallPath();

  const denied = evaluateGatewayCallPath(
    gatewayCallInput({
      gatewayRoute: {
        action: 'enrollment_gate',
        runtimeLocation: 'browser',
        locallySimulated: true,
        cacheHit: true,
        overrideApplied: true,
      },
      actionPolicy: {
        action: 'enrollment_gate',
        forbidsBrowserTrustPath: false,
        forbidsCachedOrSimulatedOutcomes: false,
        noProductionTrustClaim: false,
      },
      gatewayRequest: {
        action: 'protocol_launch',
        exochainProductionClaim: true,
      },
      gatewayResponse: {
        action: 'enrollment_gate',
        locallySimulated: true,
        cacheHit: true,
        overrideApplied: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('gateway_route_browser_runtime_forbidden'));
  assert.ok(denied.reasons.includes('gateway_route_local_simulation_forbidden'));
  assert.ok(denied.reasons.includes('gateway_route_cached_outcome_forbidden'));
  assert.ok(denied.reasons.includes('gateway_route_override_forbidden'));
  assert.ok(denied.reasons.includes('gateway_request_production_claim_forbidden'));
  assert.ok(denied.reasons.includes('gateway_action_mismatch'));
});

test('gateway call path validates HLC order route evidence and response receipt linkage', async () => {
  const { evaluateGatewayCallPath } = await loadGatewayCallPath();

  const denied = evaluateGatewayCallPath(
    gatewayCallInput({
      gatewayRoute: {
        status: 'draft',
        approvedAtHlc: { physicalMs: 1810000000000, logical: 30 },
        routeHash: 'not-a-digest',
      },
      gatewayRequest: {
        method: 'GET',
        actionHash: 'not-a-digest',
        requestHash: 'not-a-digest',
        idempotencyKeyHash: 'not-a-digest',
      },
      didAuthentication: {
        checkedAtHlc: { physicalMs: 1810000000000, logical: 40 },
      },
      validationEvidence: {
        gatewayAdapterTestsPassed: false,
        validationHash: 'not-a-digest',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('gateway_route_not_active'));
  assert.ok(denied.reasons.includes('gateway_route_hash_invalid'));
  assert.ok(denied.reasons.includes('gateway_request_method_mismatch'));
  assert.ok(denied.reasons.includes('gateway_action_hash_invalid'));
  assert.ok(denied.reasons.includes('gateway_request_hash_invalid'));
  assert.ok(denied.reasons.includes('gateway_request_idempotency_hash_invalid'));
  assert.ok(denied.reasons.includes('gateway_route_approved_after_request'));
  assert.ok(denied.reasons.includes('did_authentication_after_request'));
  assert.ok(denied.reasons.includes('validation_gateway_adapter_tests_missing'));
  assert.ok(denied.reasons.includes('validation_hash_invalid'));
  assert.ok(denied.reasons.includes('expected_action_hash_invalid'));
});

test('gateway call path rejects raw gateway payloads protected content and secrets before receipts', async () => {
  const { evaluateGatewayCallPath } = await loadGatewayCallPath();

  assert.throws(
    () =>
      evaluateGatewayCallPath(
        gatewayCallInput({
          gatewayRequest: {
            requestPayload: { sourceDocumentBody: 'source body fixture is forbidden' },
          },
        }),
      ),
    /raw gateway payload|protected content/i,
  );

  assert.throws(
    () =>
      evaluateGatewayCallPath(
        gatewayCallInput({
          gatewayRoute: {
            apiKey: 'redacted-api-key-placeholder',
          },
        }),
      ),
    /secret/i,
  );
});
