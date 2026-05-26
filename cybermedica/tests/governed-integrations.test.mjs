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
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

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

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
  DIGEST_9,
];

async function loadGovernedIntegrations() {
  try {
    return await import('../src/governed-integrations.mjs');
  } catch (error) {
    assert.fail(`CyberMedica governed integrations module must exist and load: ${error.message}`);
  }
}

function connector(type, index, overrides = {}) {
  return {
    connectorRef: `connector-${type}-alpha`,
    type,
    systemRef: `system-${type}-alpha`,
    status: 'verified',
    mode: type === 'identity_provider' ? 'inbound' : 'bidirectional',
    ownerDid: 'did:exo:integration-owner-alpha',
    configurationHash: DIGESTS[index % DIGESTS.length],
    mappingHash: DIGESTS[(index + 1) % DIGESTS.length],
    accessPolicyHash: DIGESTS[(index + 2) % DIGESTS.length],
    webhookPolicyHash: DIGESTS[(index + 3) % DIGESTS.length],
    importProfileHash: DIGESTS[(index + 4) % DIGESTS.length],
    exportProfileHash: DIGESTS[(index + 5) % DIGESTS.length],
    lastVerifiedAtHlc: { physicalMs: 1795000000000, logical: index + 10 },
    dataClasses: type === 'econsent' ? ['participant_linked_metadata', 'consent_metadata'] : ['qms_metadata'],
    metadataOnly: true,
    payloadStoredOutsideReceipt: true,
    protectedPayloadExcluded: true,
    secretsManagedExternally: true,
    failClosedOnError: true,
    retryPolicy: {
      idempotencyKeyRequired: true,
      duplicateDeliverySafe: true,
      maxRetryCount: 3,
    },
    healthCheck: {
      checkedAtHlc: { physicalMs: 1795000000000, logical: index + 40 },
      status: 'passing',
      statusHash: DIGESTS[(index + 6) % DIGESTS.length],
      rawResponseExcluded: true,
    },
    ...overrides,
  };
}

function integrationInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:system-administrator-alpha',
      kind: 'human',
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_integrations', 'read'],
      authorityChainHash: DIGEST_A,
    },
    integrationPlan: {
      planRef: 'integration-plan-site-alpha',
      planVersion: 'v1',
      approved: true,
      approvedByDid: 'did:exo:quality-manager-alpha',
      scopeHash: DIGEST_B,
      systemOfRecordPolicyHash: DIGEST_C,
      dataMinimizationHash: DIGEST_D,
      accessReviewHash: DIGEST_E,
      testedAtHlc: { physicalMs: 1795000000000, logical: 90 },
      metadataOnly: true,
      productionTrustClaim: false,
    },
    connectors: REQUIRED_CONNECTOR_TYPES.map((type, index) => connector(type, index)),
    endpointPolicy: {
      policyRef: 'api-webhook-policy-fr048-alpha',
      policyHash: DIGEST_F,
      governedApiOnly: true,
      webhookSignatureRequired: true,
      importExportFormatsApproved: true,
      leastPrivilegeScopes: true,
      rateLimitConfigured: true,
      replayProtectionEnabled: true,
      schemaVersioningRequired: true,
      rawPayloadLoggingDisabled: true,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 5 },
    },
    privacyBoundary: {
      boundaryRef: 'integration-privacy-boundary-alpha',
      phiPiiExcludedFromReceipts: true,
      sponsorConfidentialMinimized: true,
      payloadsRemainInSourceSystems: true,
      disclosureLogRequired: true,
      consentCheckedForParticipantLinkedData: true,
      boundaryHash: DIGEST_A,
    },
    disclosureLog: {
      logRef: 'integration-disclosure-log-alpha',
      loggedAtHlc: { physicalMs: 1795000000000, logical: 95 },
      disclosureLogHash: DIGEST_B,
      recipientClass: 'system_integration',
      includesRawContent: false,
    },
    custodyDigest: DIGEST_C,
    ...overrides,
  };
}

test('governed integrations verify all FR-048 connector families with deterministic inactive receipts', async () => {
  const { evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  const resultA = evaluateGovernedIntegrations(integrationInput());
  const resultB = evaluateGovernedIntegrations({
    ...integrationInput(),
    connectors: [...integrationInput().connectors].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.integrationReadiness.status, 'ready');
  assert.equal(resultA.integrationReadiness.connectorCount, REQUIRED_CONNECTOR_TYPES.length);
  assert.deepEqual(resultA.integrationReadiness.connectorTypes, REQUIRED_CONNECTOR_TYPES);
  assert.deepEqual(resultA.integrationReadiness.missingConnectorTypes, []);
  assert.equal(resultA.integrationReadiness.metadataOnly, true);
  assert.equal(resultA.integrationReadiness.exochainProductionClaim, false);
  assert.equal(resultA.integrationReadiness.readinessHash, resultB.integrationReadiness.readinessHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'governed_integrations_readiness');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw payload|client_secret|source document/iu);
});

test('governed integrations fail closed for missing connector families and unsafe endpoint policy', async () => {
  const { evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  const input = integrationInput({
    connectors: integrationInput().connectors.filter((item) => item.type !== 'edc' && item.type !== 'identity_provider'),
    endpointPolicy: {
      ...integrationInput().endpointPolicy,
      governedApiOnly: false,
      webhookSignatureRequired: false,
      replayProtectionEnabled: false,
      rawPayloadLoggingDisabled: false,
    },
  });

  const denied = evaluateGovernedIntegrations(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.integrationReadiness.status, 'blocked');
  assert.ok(denied.reasons.includes('connector_type_missing:edc'));
  assert.ok(denied.reasons.includes('connector_type_missing:identity_provider'));
  assert.ok(denied.reasons.includes('endpoint_governed_api_only_absent'));
  assert.ok(denied.reasons.includes('endpoint_webhook_signature_absent'));
  assert.ok(denied.reasons.includes('endpoint_replay_protection_absent'));
  assert.ok(denied.reasons.includes('endpoint_raw_payload_logging_forbidden'));
});

test('governed integrations deny connector payload, health, retry, and privacy boundary defects', async () => {
  const { evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  const input = integrationInput({
    connectors: [
      connector('ctms', 0, {
        status: 'failing',
        healthCheck: {
          checkedAtHlc: { physicalMs: 1795000000000, logical: 2 },
          status: 'failing',
          statusHash: 'bad',
          rawResponseExcluded: false,
        },
        metadataOnly: false,
        payloadStoredOutsideReceipt: false,
        protectedPayloadExcluded: false,
        secretsManagedExternally: false,
        failClosedOnError: false,
        retryPolicy: {
          idempotencyKeyRequired: false,
          duplicateDeliverySafe: false,
          maxRetryCount: 0,
        },
      }),
      ...integrationInput().connectors.filter((item) => item.type !== 'ctms'),
    ],
    privacyBoundary: {
      ...integrationInput().privacyBoundary,
      phiPiiExcludedFromReceipts: false,
      consentCheckedForParticipantLinkedData: false,
      payloadsRemainInSourceSystems: false,
    },
  });

  const denied = evaluateGovernedIntegrations(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.integrationReadiness.status, 'blocked');
  assert.ok(denied.reasons.includes('connector_not_verified:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_metadata_boundary_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_payload_storage_boundary_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_protected_payload_boundary_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_secret_scope_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_fail_closed_absent:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_idempotency_absent:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_duplicate_delivery_safety_absent:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_retry_count_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_health_check_hash_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_health_raw_response_forbidden:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('privacy_phi_pii_receipt_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_participant_consent_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_source_payload_boundary_invalid'));
});

test('governed integrations validate tenant authority HLC ordering and disclosure logging', async () => {
  const { evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  const denied = evaluateGovernedIntegrations({
    ...integrationInput(),
    targetTenantId: 'tenant-other',
    actor: { did: 'did:exo:ai-integration-agent', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    integrationPlan: {
      ...integrationInput().integrationPlan,
      approved: false,
      productionTrustClaim: true,
      testedAtHlc: { physicalMs: 1795000000000, logical: -1 },
    },
    disclosureLog: {
      ...integrationInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 4 },
      includesRawContent: true,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('integration_authority_missing'));
  assert.ok(denied.reasons.includes('integration_plan_not_approved'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('integration_plan_test_time_invalid'));
  assert.ok(denied.reasons.includes('disclosure_log_before_endpoint_policy'));
  assert.ok(denied.reasons.includes('disclosure_log_raw_content_forbidden'));
});

test('governed integrations reject raw connector payloads and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  assert.throws(
    () =>
      evaluateGovernedIntegrations({
        ...integrationInput(),
        connectorRawPayload: 'Participant Alice source document payload',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedIntegrations({
        ...integrationInput(),
        connectors: [
          {
            ...connector('edc', 3),
            clientSecret: 'must-not-be-stored',
          },
        ],
      }),
    ProtectedContentError,
  );
});

test('governed integrations handle inert raw markers and physical HLC disclosure ordering', async () => {
  const { ProtectedContentError, evaluateGovernedIntegrations } = await loadGovernedIntegrations();

  const sameTick = evaluateGovernedIntegrations({
    ...integrationInput(),
    connectors: [
      {
        ...connector('identity_provider', 7),
        clientSecret: {},
        rawPayload: [null, false],
      },
      ...integrationInput().connectors.filter((item) => item.type !== 'identity_provider'),
    ],
    endpointPolicy: {
      ...integrationInput().endpointPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 95 },
    },
  });

  assert.equal(sameTick.decision, 'permitted');

  const physicalBefore = evaluateGovernedIntegrations({
    ...integrationInput(),
    endpointPolicy: {
      ...integrationInput().endpointPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000001, logical: 0 },
    },
  });

  assert.equal(physicalBefore.decision, 'denied');
  assert.ok(physicalBefore.reasons.includes('disclosure_log_before_endpoint_policy'));

  assert.throws(
    () =>
      evaluateGovernedIntegrations({
        ...integrationInput(),
        rawPayload: [{ unexpected: 'source payload body' }],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedIntegrations({
        ...integrationInput(),
        rawPayload: 1,
      }),
    ProtectedContentError,
  );
});
